import Foundation
import SQLite3

/// 本地索引：文件指纹 + 命中记录。全部落在 ~/Library/Application Support/保密检查/index.db。
/// 只存路径与命中摘要，不存文件内容。
final class Store {
    private var db: OpaquePointer?
    let path: String
    /// 判定口径的版本：改一次这里，就会清索引重扫一遍（见 init）
    static let rulesVersion = "3"
    /// 后台扫描与界面会同时访问；自己加锁，不指望驱动层的线程模式
    private let lock = NSLock()

    init(path: String) {
        self.path = path
        try? FileManager.default.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true)
        guard sqlite3_open(path, &db) == SQLITE_OK else {
            Log.w("store: 打不开 \(path)")
            return
        }
        sqlite3_busy_timeout(db, 3000)
        exec("PRAGMA journal_mode=WAL;")
        exec("PRAGMA synchronous=NORMAL;")
        exec("CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, mtime REAL, size INTEGER, scanned_at REAL);")
        exec("""
        CREATE TABLE IF NOT EXISTS findings(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          path TEXT, kind TEXT, level INTEGER, place TEXT,
          value TEXT, note TEXT, ctx TEXT, via_ocr INTEGER, found_at REAL);
        """)
        exec("CREATE INDEX IF NOT EXISTS idx_find_level ON findings(level DESC, found_at DESC);")
        exec("CREATE INDEX IF NOT EXISTS idx_find_path ON findings(path);")
        exec("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);")
        // 口径收紧：只留「密级标志」里的国家秘密 / 工作秘密，加「无法检查」。
        // 旧版本留下的内部资料、证件号、文档属性、修订、批注、照片位置等记录一次清掉，
        // 否则它们会以新标签重新出现在清单里
        exec("DELETE FROM findings WHERE kind NOT IN ('密级标志','无法检查');")
        exec("DELETE FROM findings WHERE kind='密级标志' AND level=1 AND value<>'工作秘密';")

        // 判定规则一换，旧结论就不可信了；指纹也得一起清，否则没改过的文件永远不会被重判
        // （只删命中不清指纹，就会留下按旧规则判出来的假阳性）
        if meta("rulesVersion") != Self.rulesVersion {
            exec("DELETE FROM findings;")
            exec("DELETE FROM files;")
            setMeta("rulesVersion", Self.rulesVersion)
            Log.w("store: 判定规则换代（\(Self.rulesVersion)），索引已清空，等一次全量重扫")
        }
    }

    deinit { sqlite3_close(db) }

    // MARK: 基础

    private func exec(_ sql: String) {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            Log.w("store: sql 失败 \(String(cString: sqlite3_errmsg(db)))")
            return
        }
    }

    private func bind(_ st: OpaquePointer?, _ idx: Int32, _ s: String) {
        sqlite3_bind_text(st, idx, s, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
    }

    private func run(_ sql: String, _ binds: [Any], step: Bool = true) {
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK, let st else {
            Log.w("store: prepare 失败 \(String(cString: sqlite3_errmsg(db)))")
            return
        }
        for (i, v) in binds.enumerated() {
            let idx = Int32(i + 1)
            switch v {
            case let s as String:  bind(st, idx, s)
            case let d as Double:  sqlite3_bind_double(st, idx, d)
            case let n as Int:     sqlite3_bind_int64(st, idx, Int64(n))
            default: break
            }
        }
        if step { sqlite3_step(st) }
    }

    private func text(_ st: OpaquePointer?, _ i: Int32) -> String {
        guard let c = sqlite3_column_text(st, i) else { return "" }
        return String(cString: c)
    }

    // MARK: 文件指纹

    func fileState(_ path: String) -> (mtime: Double, size: Int)? {
        lock.lock(); defer { lock.unlock() }
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, "SELECT mtime, size FROM files WHERE path=?1", -1, &st, nil) == SQLITE_OK
        else { return nil }
        bind(st, 1, path)
        guard sqlite3_step(st) == SQLITE_ROW else { return nil }
        return (sqlite3_column_double(st, 0), Int(sqlite3_column_int64(st, 1)))
    }

    func markScanned(_ path: String, mtime: Double, size: Int) {
        lock.lock(); defer { lock.unlock() }
        run("""
        INSERT INTO files(path,mtime,size,scanned_at) VALUES(?1,?2,?3,?4)
        ON CONFLICT(path) DO UPDATE SET mtime=?2,size=?3,scanned_at=?4
        """, [path, mtime, size, Date().timeIntervalSince1970])
    }

    // MARK: 一轮扫描的"见过"集合（清理幽灵用）

    func beginSweep() {
        lock.lock(); defer { lock.unlock() }
        exec("CREATE TEMP TABLE IF NOT EXISTS seen(path TEXT PRIMARY KEY);")
        exec("DELETE FROM seen;")
    }

    func markSeen(_ path: String) {
        lock.lock(); defer { lock.unlock() }
        run("INSERT OR IGNORE INTO seen(path) VALUES(?1)", [path])
    }

    /// 本轮不完整（停止/触顶）：只丢弃 seen，绝不动已有索引
    func abandonSweep() {
        lock.lock(); defer { lock.unlock() }
        exec("DELETE FROM seen;")
    }

    /// 本轮没见到的文件从索引里删掉；对应命中一起删
    func endSweep() {
        // 分批处理，每批重新拿锁，避免几万行删到一半界面全冻住
        exec("CREATE TEMP TABLE IF NOT EXISTS gone(path TEXT PRIMARY KEY);")
        exec("DELETE FROM gone;")
        lock.lock()
        exec("INSERT INTO gone(path) SELECT path FROM files WHERE path NOT IN (SELECT path FROM seen);")
        lock.unlock()

        exec("CREATE TEMP TABLE IF NOT EXISTS batch(path TEXT PRIMARY KEY);")
        while true {
            lock.lock()
            exec("DELETE FROM batch;")
            exec("INSERT INTO batch SELECT path FROM gone LIMIT 2000;")
            let any = sqlite3_changes(db) > 0
            if !any {
                exec("DELETE FROM gone;")
                lock.unlock()
                break
            }
            exec("DELETE FROM findings WHERE path IN (SELECT path FROM batch);")
            exec("DELETE FROM files WHERE path IN (SELECT path FROM batch);")
            exec("DELETE FROM gone WHERE path IN (SELECT path FROM batch);")
            exec("DELETE FROM batch;")
            lock.unlock()
        }
        lock.lock()
        exec("DELETE FROM seen;")
        lock.unlock()
    }

    // MARK: 命中

    func replaceFindings(path: String, with hits: [ConfFinding]) {
        lock.lock(); defer { lock.unlock() }
        run("DELETE FROM findings WHERE path=?1", [path])
        guard !hits.isEmpty else { return }
        exec("BEGIN;")
        for h in hits {
            run("""
            INSERT INTO findings(path,kind,level,place,value,note,ctx,via_ocr,found_at)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
            """, [path, h.kind.rawValue, h.level.rawValue, h.place, h.value, h.note, h.context,
                  h.viaOCR ? 1 : 0, Date().timeIntervalSince1970])
        }
        exec("COMMIT;")
    }

    /// 磁盘上已经不存在，连记录一起清掉，别留幽灵
    func forget(_ path: String) {
        lock.lock(); defer { lock.unlock() }
        run("DELETE FROM findings WHERE path=?1", [path])
        run("DELETE FROM files WHERE path=?1", [path])
    }

    struct Row {
        var path: String
        var kind: String
        var level: Int
        var place: String
        var value: String
        var note: String
        var ctx: String
    }

    func findingsCount(minLevel: Int = 0) -> Int {
        lock.lock(); defer { lock.unlock() }
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM findings WHERE level >= ?1", -1, &st, nil) == SQLITE_OK else { return 0 }
        sqlite3_bind_int(st, 1, Int32(minLevel))
        guard
              sqlite3_step(st) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int(st, 0))
    }

    func findings(limit: Int = 50, offset: Int = 0, minLevel: Int = 0) -> [Row] {
        lock.lock(); defer { lock.unlock() }
        var out: [Row] = []
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, """
        SELECT path,kind,level,place,value,note,ctx FROM findings
        WHERE level >= ?3
        ORDER BY level DESC, found_at DESC LIMIT ?1 OFFSET ?2
        """, -1, &st, nil) == SQLITE_OK else { return out }
        sqlite3_bind_int(st, 1, Int32(limit))
        sqlite3_bind_int(st, 2, Int32(offset))
        sqlite3_bind_int(st, 3, Int32(minLevel))
        while sqlite3_step(st) == SQLITE_ROW {
            out.append(Row(path: text(st, 0), kind: text(st, 1), level: Int(sqlite3_column_int(st, 2)),
                           place: text(st, 3), value: text(st, 4), note: text(st, 5), ctx: text(st, 6)))
        }
        return out
    }

    func counts() -> (secret: Int, work: Int, info: Int, files: Int) {
        lock.lock(); defer { lock.unlock() }
        var secret = 0, work = 0, info = 0, files = 0
        var st: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT level, COUNT(*) FROM findings GROUP BY level", -1, &st, nil) == SQLITE_OK {
            while sqlite3_step(st) == SQLITE_ROW {
                let level = Int(sqlite3_column_int(st, 0))
                let n = Int(sqlite3_column_int(st, 1))
                if level >= SecretLevel.secret.rawValue { secret += n }
                else if level == SecretLevel.workSecret.rawValue { work += n }
                else { info += n }
            }
        }
        sqlite3_finalize(st)
        var fst: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM files", -1, &fst, nil) == SQLITE_OK,
           sqlite3_step(fst) == SQLITE_ROW {
            files = Int(sqlite3_column_int(fst, 0))
        }
        sqlite3_finalize(fst)
        return (secret, work, info, files)
    }

    func setMeta(_ key: String, _ value: String) {
        lock.lock(); defer { lock.unlock() }
        run("INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=?2", [key, value])
    }

    func meta(_ key: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key=?1", -1, &st, nil) == SQLITE_OK
        else { return nil }
        bind(st, 1, key)
        guard sqlite3_step(st) == SQLITE_ROW else { return nil }
        return text(st, 0)
    }
}
