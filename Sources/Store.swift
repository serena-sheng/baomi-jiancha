import Foundation
import SQLite3

/// 本地索引：文件指纹 + 命中记录。全部落在 ~/Library/Application Support/保密检查/index.db。
/// 只存路径与命中摘要，不存文件内容。
final class Store {
    private var db: OpaquePointer?
    let path: String
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
        exec("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);")
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

    /// 本轮没见到的文件从索引里删掉；对应命中一起删
    func endSweep() {
        lock.lock(); defer { lock.unlock() }
        exec("DELETE FROM files WHERE path NOT IN (SELECT path FROM seen);")
        exec("DELETE FROM findings WHERE path NOT IN (SELECT path FROM files);")
        exec("DELETE FROM seen;")
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

    func findings(limit: Int = 800) -> [Row] {
        lock.lock(); defer { lock.unlock() }
        var out: [Row] = []
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, """
        SELECT path,kind,level,place,value,note,ctx FROM findings
        ORDER BY level DESC, found_at DESC LIMIT ?1
        """, -1, &st, nil) == SQLITE_OK else { return out }
        sqlite3_bind_int(st, 1, Int32(limit))
        while sqlite3_step(st) == SQLITE_ROW {
            out.append(Row(path: text(st, 0), kind: text(st, 1), level: Int(sqlite3_column_int(st, 2)),
                           place: text(st, 3), value: text(st, 4), note: text(st, 5), ctx: text(st, 6)))
        }
        return out
    }

    func counts() -> (secret: Int, internalCount: Int, info: Int, files: Int) {
        lock.lock(); defer { lock.unlock() }
        var secret = 0, internalCount = 0, info = 0, files = 0
        var st: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT level, COUNT(*) FROM findings GROUP BY level", -1, &st, nil) == SQLITE_OK {
            while sqlite3_step(st) == SQLITE_ROW {
                let level = Int(sqlite3_column_int(st, 0))
                let n = Int(sqlite3_column_int(st, 1))
                if level >= SecretLevel.secret.rawValue { secret += n }
                else if level == SecretLevel.internalOnly.rawValue { internalCount += n }
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
        return (secret, internalCount, info, files)
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
