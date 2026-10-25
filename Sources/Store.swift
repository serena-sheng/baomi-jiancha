import Foundation
import SQLite3

/// 本地索引：文件指纹 + 命中记录。全部落在 ~/Library/Application Support/保密检查/index.db。
/// 只存路径与命中摘要，不存文件内容。
final class Store {
    private var db: OpaquePointer?
    let path: String
    /// 判定口径的版本：改一次这里，就会清索引重扫一遍（见 init）
    static let rulesVersion = "5"   // 5: 谈论语言（表格、字样）不再算标志
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
        // 抑制规则：把「自己产物的噪声」挡在报警之外，但不删记录、不改判定。
        // 三条红线：① 绝密默认不可 hide ② kind='无法检查' 永不参与抑制 ③ 只作用显示与计数，不动 findings 原始行。
        exec("""
        CREATE TABLE IF NOT EXISTS suppressions(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scope TEXT NOT NULL,             -- dir | suffix | glob
          pattern TEXT NOT NULL,           -- 绝对目录 / .png / *截图*.png
          via_ocr INTEGER,                 -- NULL=不限 0=仅正文 1=仅 OCR
          min_level INTEGER NOT NULL DEFAULT 2,
          max_level INTEGER NOT NULL DEFAULT 3,
          mode TEXT NOT NULL DEFAULT 'mute',   -- mute=不叫人但清单可见 | hide=清单默认隐藏
          note TEXT,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at REAL);
        """)
        exec("CREATE INDEX IF NOT EXISTS idx_supp_enabled ON suppressions(enabled, scope);")
        // 早期版本把 nil 写成 -1，规则会永远匹配不上；顺手清一遍
        exec("UPDATE suppressions SET via_ocr=NULL WHERE via_ocr<0;")
        // 早期默认种过一条「~/dev 整目录」规则，会把开发者导出的真涉密文件一起静音，删掉
        exec("DELETE FROM suppressions WHERE scope='dir' AND note LIKE '%源码目录%';")
        if !hasColumn("findings", "muted") {
            exec("ALTER TABLE findings ADD COLUMN muted INTEGER NOT NULL DEFAULT 0;")
        }
        exec("CREATE INDEX IF NOT EXISTS idx_find_muted ON findings(muted, level DESC);")
        // 「这不是涉密」：用户否证过一次的判断。键带 size+mtime+口径版本，
        // 文件一被改写、口径一换代，这个否证就自动失效——不然它会变成永久失明。
        exec("""
        CREATE TABLE IF NOT EXISTS dismissals(
          path TEXT PRIMARY KEY,
          size INTEGER NOT NULL,
          mtime REAL NOT NULL,
          rules TEXT NOT NULL,
          at REAL NOT NULL);
        """)
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

        // 默认规则集换代：只替换我们自己种下的那几条，用户自建的原样保留
        if meta("suppressVersion") != "3" {
            exec("""
            DELETE FROM suppressions
            WHERE note LIKE '%源码目录%' OR note LIKE '%画面内容%' OR note = '同 .png'
            """)
            exec("DELETE FROM meta WHERE key='suppressSeeded'")
            setMeta("suppressVersion", "3")
        }

        // 抑制规则是用户意图，不随判定口径换代清空；命中状态要跟着当前库重算一次
        seedDefaultSuppressionsIfNeeded()
        recomputeMuted()
    }

    deinit { sqlite3_close(db) }

    // MARK: 基础

    private func exec(_ sql: String) {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            Log.w("store: sql 失败 \(String(cString: sqlite3_errmsg(db)))")
            return
        }
    }

    /// 判断某表是否已有某列（迁移用）
    private func hasColumn(_ table: String, _ col: String) -> Bool {
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, "PRAGMA table_info(\(table))", -1, &st, nil) == SQLITE_OK else { return false }
        while sqlite3_step(st) == SQLITE_ROW {
            if text(st, 1) == col { return true }
        }
        return false
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
            // Int64 不绑就等于 WHERE 传了 NULL：UPDATE 会静默命中 0 行
            case let n as Int64:   sqlite3_bind_int64(st, idx, n)
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
        // 入库时就算好抑制状态：否则每个文件一次全表重算，扫描会变成 O(n²)
        let rules = readSuppressionsLocked().filter { $0.enabled }
        exec("BEGIN;")
        for h in hits {
            let muted = (h.kind.rawValue == "密级标志" && !rules.isEmpty)
                ? suppressionMode(path: path, level: h.level.rawValue, ocr: h.viaOCR ? 1 : 0, rules: rules)
                : 0
            run("""
            INSERT INTO findings(path,kind,level,place,value,note,ctx,via_ocr,found_at,muted)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
            """, [path, h.kind.rawValue, h.level.rawValue, h.place, h.value, h.note, h.context,
                  h.viaOCR ? 1 : 0, Date().timeIntervalSince1970, muted])
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

    func findingsCount(minLevel: Int = 0, suppressedOnly: Bool = false) -> Int {
        lock.lock(); defer { lock.unlock() }
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        let whereMuted = suppressedOnly ? "muted>0" : "muted=0"
        let sql = """
        SELECT COUNT(*) FROM findings f
        LEFT JOIN files fl ON fl.path = f.path
        LEFT JOIN dismissals d ON d.path = f.path AND d.rules = ?2
             AND d.size = fl.size AND abs(d.mtime - fl.mtime) < 0.001
        WHERE f.level >= ?1 AND f.\(whereMuted) AND d.path IS NULL
        """
        guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else { return 0 }
        sqlite3_bind_int(st, 1, Int32(minLevel))
        bind(st, 2, Self.rulesVersion)
        guard
              sqlite3_step(st) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int(st, 0))
    }

    func findings(limit: Int = 50, offset: Int = 0, minLevel: Int = 0,
                  suppressedOnly: Bool = false) -> [Row] {
        lock.lock(); defer { lock.unlock() }
        var out: [Row] = []
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        let whereMuted = suppressedOnly ? "muted>0" : "muted=0"
        let sql = """
        SELECT f.path,f.kind,f.level,f.place,f.value,f.note,f.ctx FROM findings f
        LEFT JOIN files fl ON fl.path = f.path
        LEFT JOIN dismissals d ON d.path = f.path AND d.rules = ?4
             AND d.size = fl.size AND abs(d.mtime - fl.mtime) < 0.001
        WHERE f.level >= ?3 AND f.\(whereMuted) AND d.path IS NULL
        ORDER BY f.level DESC, f.found_at DESC LIMIT ?1 OFFSET ?2
        """
        guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else { return out }
        sqlite3_bind_int(st, 1, Int32(limit))
        sqlite3_bind_int(st, 2, Int32(offset))
        sqlite3_bind_int(st, 3, Int32(minLevel))
        bind(st, 4, Self.rulesVersion)
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
        // 计数必须和清单同一口径：漏了 dismissals 的 JOIN，会出现
        // 「行消失了、表头数字还在」——那比不消失更让人怀疑
        let sql = """
        SELECT f.level, COUNT(*) FROM findings f
        LEFT JOIN files fl ON fl.path = f.path
        LEFT JOIN dismissals d ON d.path = f.path AND d.rules = ?1
             AND d.size = fl.size AND abs(d.mtime - fl.mtime) < 0.001
        WHERE f.muted = 0 AND d.path IS NULL
        GROUP BY f.level
        """
        if sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK {
            bind(st, 1, Self.rulesVersion)
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

// MARK: - 抑制规则
//
// 噪声明明是真的（截图里确实有「绝密」二字），但它不该占据报警位。
// 所以抑制只作用「叫人」与「清单默认可见性」，从不删除、从不改判定。
// 三条红线见 Store.init 的建表注释。

struct Suppression {
    var id: Int64 = 0
    var scope: String = "dir"          // dir | suffix | glob
    var pattern: String = ""
    var viaOCR: Int? = nil             // nil = 不限；0 = 仅正文；1 = 仅 OCR
    var minLevel: Int = 2
    var maxLevel: Int = 3
    var mode: String = "mute"          // mute | hide
    var note: String = ""
    var enabled: Bool = true

    /// 越具体越优先：dir > suffix > glob；同类比 pattern 长度
    var specificity: (Int, Int) {
        switch scope {
        case "dir":    return (3, pattern.count)
        case "suffix": return (2, pattern.count)
        default:       return (1, pattern.filter { $0 != "*" && $0 != "?" }.count)
        }
    }
}

/// 只支持 * 与 ?，够用且可预期；不引入正则，避免规则写错很难看出来
private func globMatch(_ pattern: String, _ text: String) -> Bool {
    let p = Array(pattern), t = Array(text)
    var pi = 0, ti = 0, star = -1, mark = 0
    while ti < t.count {
        if pi < p.count && (p[pi] == "?" || p[pi] == t[ti]) {
            pi += 1; ti += 1
        } else if pi < p.count && p[pi] == "*" {
            star = pi; mark = ti; pi += 1
        } else if star >= 0 {
            pi = star + 1; mark += 1; ti = mark
        } else {
            return false
        }
    }
    while pi < p.count && p[pi] == "*" { pi += 1 }
    return pi == p.count
}

extension Store {
    private func readSuppressionsLocked() -> [Suppression] {
        var out: [Suppression] = []
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, """
        SELECT id,scope,pattern,via_ocr,min_level,max_level,mode,note,enabled
        FROM suppressions ORDER BY id
        """, -1, &st, nil) == SQLITE_OK else { return out }
        while sqlite3_step(st) == SQLITE_ROW {
            var s = Suppression()
            s.id = sqlite3_column_int64(st, 0)
            s.scope = text(st, 1)
            s.pattern = text(st, 2)
            // -1 是历史上把 nil 写成 int 的坏数据，一并当 NULL 读
            let via = sqlite3_column_type(st, 3) == SQLITE_NULL ? -1 : Int(sqlite3_column_int(st, 3))
            s.viaOCR = via < 0 ? nil : via
            s.minLevel = Int(sqlite3_column_int(st, 4))
            s.maxLevel = Int(sqlite3_column_int(st, 5))
            s.mode = text(st, 6)
            s.note = text(st, 7)
            s.enabled = sqlite3_column_int(st, 8) != 0
            out.append(s)
        }
        return out
    }

    func suppressions() -> [Suppression] {
        lock.lock(); defer { lock.unlock() }
        return readSuppressionsLocked()
    }

    @discardableResult
    func addSuppression(scope: String, pattern: String, viaOCR: Int? = nil,
                        minLevel: Int = 2, maxLevel: Int = 3,
                        mode: String = "mute", note: String = "", enabled: Bool = true) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        if let via = viaOCR {
            run("""
            INSERT INTO suppressions(scope,pattern,via_ocr,min_level,max_level,mode,note,enabled,created_at)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
            """, [scope, pattern, via, minLevel, maxLevel, mode, note,
                  enabled ? 1 : 0, Date().timeIntervalSince1970])
        } else {
            run("""
            INSERT INTO suppressions(scope,pattern,via_ocr,min_level,max_level,mode,note,enabled,created_at)
            VALUES(?1,?2,NULL,?3,?4,?5,?6,?7,?8)
            """, [scope, pattern, minLevel, maxLevel, mode, note,
                  enabled ? 1 : 0, Date().timeIntervalSince1970])
        }
        let id = sqlite3_last_insert_rowid(db)
        recomputeMutedLocked()
        return id
    }

    func setSuppressionEnabled(_ id: Int64, _ enabled: Bool) {
        lock.lock(); defer { lock.unlock() }
        run("UPDATE suppressions SET enabled=?2 WHERE id=?1", [id, enabled ? 1 : 0])
        recomputeMutedLocked()
    }

    func removeSuppression(_ id: Int64) {
        lock.lock(); defer { lock.unlock() }
        run("DELETE FROM suppressions WHERE id=?1", [id])
        recomputeMutedLocked()
    }

    /// 首次运行种下默认规则。D2 只静音「秘密」级 OCR 命中：图片里的「机密」也可能是真扫描件，宁可多报。
    func seedDefaultSuppressionsIfNeeded() {
        lock.lock()
        let existing = readSuppressionsLocked()
        let seeded = metaLocked("suppressSeeded") == "1"
        lock.unlock()
        guard !seeded, existing.isEmpty else { return }

        // 不用「整个目录」规则：~/dev 下也可能有真的涉密导出文件，
        // 整目录一压就等于给开发者开了后门。只压「图片里 OCR 出来的秘密/机密」：
        // 那是画面内容，不是文件自身的密级标志；绝密仍由红线兜住。
        let rules: [(String, String, Int?, Int, Int, String)] = [
            ("suffix", ".png", 1, 2, 4, "截图画面里的密级字样是画面内容，不是文件自身的标志"),
            ("suffix", ".jpg", 1, 2, 4, "同 .png"),
            ("suffix", ".jpeg", 1, 2, 4, "同 .png"),
            ("suffix", ".heic", 1, 2, 4, "同 .png"),
            ("suffix", ".tif", 1, 2, 4, "同 .png"),
            ("suffix", ".tiff", 1, 2, 4, "同 .png"),
        ]
        for r in rules {
            addSuppression(scope: r.0, pattern: r.1, viaOCR: r.2,
                           minLevel: r.3, maxLevel: r.4, note: r.5)
        }
        lock.lock()
        run("INSERT INTO meta(key,value) VALUES('suppressSeeded','1') ON CONFLICT(key) DO UPDATE SET value='1'", [])
        lock.unlock()
        Log.w("store: 已种下 \(rules.count) 条默认不报规则")
    }

    /// 把抑制状态刷进 findings.muted：1 = 不叫人但清单可见，2 = 清单默认隐藏，0 = 正常
    func recomputeMuted() {
        lock.lock(); defer { lock.unlock() }
        recomputeMutedLocked()
    }
}

/// 一条命中属于哪档：0 正常 / 1 不叫人但可见 / 2 清单隐藏。规则取最具体的一条。
/// 抽成 file-scope 函数是因为命令行 `--scan` 也要用同一套口径，
/// 否则窗口说「干净」、命令行说「33 处命中」，等于一份事实两处实现。
func suppressionMode(path: String, level: Int, ocr: Int, rules: [Suppression]) -> Int {
    // 红线：正文里判出的绝密不可抑制。写在代码里而不是只靠规则的 max_level，
    // 因为规则可以被改高，而这条不该被任何配置绕过。
    // 但「图片里 OCR 出来的绝密」不在此列：那可能是界面截图、海报、书封，
    // 机器认字认错了不该让规则替它背锅——这类只允许进「已忽略」，并且必须列得出来。
    if level >= 4 && ocr == 0 { return 0 }
    var best: Suppression?
    for r in rules {
        guard level >= r.minLevel, level <= r.maxLevel else { continue }
        if let want = r.viaOCR, want != ocr { continue }
        let hit: Bool
        switch r.scope {
        case "dir":
            hit = path == r.pattern || path.hasPrefix(r.pattern + "/")
        case "suffix":
            hit = path.lowercased().hasSuffix(r.pattern.lowercased())
        default:
            hit = globMatch(r.pattern, (path as NSString).lastPathComponent)
        }
        guard hit else { continue }
        if let b = best {
            let (br, bl) = b.specificity, (nr, nl) = r.specificity
            if nr > br || (nr == br && nl > bl) { best = r }
        } else {
            best = r
        }
    }
    guard let b = best else { return 0 }
    return b.mode == "hide" ? 2 : 1
}

extension Store {
    private func recomputeMutedLocked() {
        let rules = readSuppressionsLocked().filter { $0.enabled }
        guard !rules.isEmpty else {
            exec("UPDATE findings SET muted=0;")
            return
        }
        // 只取够判定的列；kind 已在 SQL 里限定，「无法检查」永不参与抑制
        var rows: [(Int64, String, Int, Int)] = []
        var st: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT id,path,level,via_ocr FROM findings WHERE kind='密级标志'",
                              -1, &st, nil) == SQLITE_OK {
            while sqlite3_step(st) == SQLITE_ROW {
                rows.append((sqlite3_column_int64(st, 0), text(st, 1),
                             Int(sqlite3_column_int(st, 2)), Int(sqlite3_column_int(st, 3))))
            }
        }
        sqlite3_finalize(st)

        exec("UPDATE findings SET muted=0 WHERE kind='密级标志';")
        exec("BEGIN;")
        for (id, path, level, ocr) in rows {
            let mode = suppressionMode(path: path, level: level, ocr: ocr, rules: rules)
            if mode > 0 { run("UPDATE findings SET muted=?2 WHERE id=?1", [id, mode]) }
        }
        exec("COMMIT;")
        Log.w("store: 抑制重算完成，规则 \(rules.count) 条，命中 \(rows.count) 条")
    }

    /// 被抑制的条数（mute + hide），用于界面「显示被抑制的 N 条」
    func suppressedCount() -> Int {
        lock.lock(); defer { lock.unlock() }
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM findings WHERE muted>0", -1, &st, nil) == SQLITE_OK,
              sqlite3_step(st) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int(st, 0))
    }

    private func metaLocked(_ k: String) -> String? {
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        guard sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key=?1", -1, &st, nil) == SQLITE_OK else { return nil }
        bind(st, 1, k)
        guard sqlite3_step(st) == SQLITE_ROW else { return nil }
        return text(st, 0)
    }
    // MARK: - 「这不是涉密」
    //
    // 机器的怀疑必须能被用户否证，且否证要记住——但只在文件没变、口径没变时记住。
    // 键 = path + size + mtime + rulesVersion：任一变化即自动失效，避免否证变成永久失明。

    func addDismissal(path: String) {
        lock.lock(); defer { lock.unlock() }
        var size = 0, mtime = 0.0
        var st: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT size, mtime FROM files WHERE path=?1", -1, &st, nil) == SQLITE_OK {
            bind(st, 1, path)
            if sqlite3_step(st) == SQLITE_ROW {
                size = Int(sqlite3_column_int64(st, 0))
                mtime = sqlite3_column_double(st, 1)
            }
        }
        sqlite3_finalize(st)
        if size == 0 && mtime == 0 {
            // files 里没有就现读，别把 size=0 写进去——那会让校验永远对不上
            if let a = try? FileManager.default.attributesOfItem(atPath: path) {
                size = Int((a[.size] as? Int64) ?? 0)
                mtime = (a[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
            }
        }
        run("""
        INSERT INTO dismissals(path,size,mtime,rules,at) VALUES(?1,?2,?3,?4,?5)
        ON CONFLICT(path) DO UPDATE SET size=?2, mtime=?3, rules=?4, at=?5
        """, [path, size, mtime, Self.rulesVersion, Date().timeIntervalSince1970])
    }

    func removeDismissal(path: String) {
        lock.lock(); defer { lock.unlock() }
        run("DELETE FROM dismissals WHERE path=?1", [path])
    }

    func clearDismissals() {
        lock.lock(); defer { lock.unlock() }
        run("DELETE FROM dismissals", [])
    }

    /// 当前仍生效的否证条数（口径换代或文件改动之后，旧的自然不计数）
    func dismissalCount() -> Int {
        lock.lock(); defer { lock.unlock() }
        var st: OpaquePointer?
        defer { sqlite3_finalize(st) }
        let sql = """
        SELECT COUNT(*) FROM dismissals d
        LEFT JOIN files fl ON fl.path = d.path
        WHERE d.rules = ?1 AND (fl.path IS NULL OR (d.size = fl.size AND abs(d.mtime - fl.mtime) < 0.001))
        """
        guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else { return 0 }
        bind(st, 1, Self.rulesVersion)
        guard sqlite3_step(st) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int(st, 0))
    }

}
