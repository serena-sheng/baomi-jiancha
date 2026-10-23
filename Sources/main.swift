// 保密检查 — macOS 常驻后台全盘扫描
// 只读检查：找密级标志、内部痕迹、证件号、文档属性、扫描件里的字。
// 本地、离线、不写内容进日志；结果存本机 SQLite。
import Cocoa
import SwiftUI
import CoreServices

// MARK: - 日志

enum Log {
    static let path = NSHomeDirectory() + "/Library/Logs/baomi.log"
    static func w(_ msg: String) {
        let line = "\(Date()) \(msg)\n"
        let url = URL(fileURLWithPath: path)
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile()
            h.write(Data(line.utf8))
            try? h.close()
        } else {
            try? line.data(using: .utf8)?.write(to: url)
        }
    }
}

// MARK: - 配置

enum Config {
    static let supportDir = NSHomeDirectory() + "/Library/Application Support/保密检查"
    static let dbPath = supportDir + "/index.db"
    static let appPath = "/Applications/保密检查.app"
    /// 不进去的地方：缓存、包、版本库、照片库、回收站
    static let excludeNames: Set<String> = [
        "node_modules", ".git", ".Trash", "Caches", "DerivedData",
        "Photos Library.photoslibrary", "Library", ".build", "build",
    ]
    static let excludeSuffixes = [".photoslibrary", ".framework", ".appex", ".xcodeproj"]
    static let maxFileBytes: Int64 = 60 * 1024 * 1024
    static let maxFiles = 2_000_000
}

// MARK: - 扫描器

final class Scanner {
    private let store: Store
    private var work: DispatchWorkItem?
    private var stopFlag = false
    private let lock = NSLock()

    private(set) var scanning = false
    private(set) var scanned = 0
    private(set) var total = 0
    private(set) var lastFinish: Date?
    private(set) var needsFullDisk = false
    var onChange: (() -> Void)?

    init(store: Store) { self.store = store }

    static func roots() -> [URL] {
        // 测试用：BAOMI_ROOTS 可把扫描范围限制在几个目录
        if let env = ProcessInfo.processInfo.environment["BAOMI_ROOTS"], !env.isEmpty {
            return env.split(separator: ":").map { URL(fileURLWithPath: String($0)) }
        }
        var roots = [URL(fileURLWithPath: NSHomeDirectory())]
        let vol = URL(fileURLWithPath: "/Volumes")
        if let items = try? FileManager.default.contentsOfDirectory(at: vol, includingPropertiesForKeys: nil) {
            for u in items where !u.lastPathComponent.hasPrefix(".") {
                // 系统卷不重复扫；Time Machine 之类的先跳过
                if u.lastPathComponent == "Macintosh HD" { continue }
                roots.append(u)
            }
        }
        return roots
    }

    func start() {
        lock.lock(); defer { lock.unlock() }
        guard !scanning else { return }
        stopFlag = false
        scanning = true
        onChange?()
        let item = DispatchWorkItem { [weak self] in self?.run() }
        work = item
        DispatchQueue.global(qos: .utility).async(execute: item)
    }

    func stop() {
        lock.lock()
        stopFlag = true
        lock.unlock()
        Log.w("scan: 收到停止")
    }

    private func isStopped() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return stopFlag
    }

    private func run() {
        let started = Date()
        let fm = FileManager.default
        needsFullDisk = !fm.isReadableFile(atPath: NSHomeDirectory() + "/Library/Mail")

        // 先收文件清单：只收我们真要读的
        store.beginSweep()
        var files: [URL] = []
        for root in Self.roots() {
            guard !isStopped() else { break }
            guard let en = fm.enumerator(at: root,
                                         includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey],
                                         options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { continue }
            for case let u as URL in en {
                if files.count >= Config.maxFiles || isStopped() { break }
                let name = u.lastPathComponent
                if Config.excludeNames.contains(name) { en.skipDescendants(); continue }
                if Config.excludeSuffixes.contains(where: { name.hasSuffix($0) }) {
                    en.skipDescendants(); continue
                }
                if (try? u.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true {
                    files.append(u)
                    store.markSeen(u.path)
                }
            }
        }

        DispatchQueue.main.async {
            self.total = files.count
            self.scanned = 0
            self.onChange?()
        }
        Log.w("scan: 起点 \(files.count) 个文件")

        for (i, u) in files.enumerated() {
            if isStopped() { break }
            autoreleasepool {
                inspect(u)
            }
            if i % 40 == 0 {
                let n = i
                DispatchQueue.main.async {
                    self.scanned = n
                    self.onChange?()
                }
            }
        }

        store.endSweep()
        DispatchQueue.main.async {
            self.scanning = false
            self.scanned = files.count
            self.lastFinish = Date()
            self.onChange?()
        }
        let secs = Date().timeIntervalSince(started)
        Log.w(String(format: "scan: 完成 %d 个文件，%.1f 秒，命中 secret=%d internal=%d",
                     files.count, secs,
                     store.counts().secret, store.counts().internalCount))
    }

    private func inspect(_ u: URL) {
        let fm = FileManager.default
        let v = try? u.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
        let size = v?.fileSize ?? 0
        let mtime = v?.contentModificationDate?.timeIntervalSince1970 ?? 0

        // 没变过就跳过：这是常驻扫描能跑得动的关键
        if let old = store.fileState(u.path), old.size == size, abs(old.mtime - mtime) < 1 { return }

        guard fm.fileExists(atPath: u.path) else { store.forget(u.path); return }

        if Int64(size) > Config.maxFileBytes {
            store.replaceFindings(path: u.path, with: [
                ConfFinding(kind: .unscannable, file: u.lastPathComponent, place: "—",
                            value: Fmt.bytes(Int64(size)), note: "文件太大，没查内容", level: .info)
            ])
            store.markScanned(u.path, mtime: mtime, size: size)
            return
        }

        var r = Confidential.Result()
        Confidential.inspectFileForCLI(u, ocr: true, into: &r)
        let hits = r.findings
        store.replaceFindings(path: u.path, with: hits)
        store.markScanned(u.path, mtime: mtime, size: size)
        if hits.contains(where: { $0.level.isStateSecret }) {
            Log.w("hit: 国家秘密标志 \(u.path)")
        }
    }
}

// MARK: - 索引模型（给界面用）

final class Model: ObservableObject {
    @Published var rows: [Store.Row] = []
    @Published var secret = 0
    @Published var internalCount = 0
    @Published var info = 0
    @Published var files = 0
    @Published var scanning = false
    @Published var scanned = 0
    @Published var total = 0
    @Published var lastFinish: String = "还没扫过"
    @Published var needsFullDisk = false
}

// MARK: - 界面

struct RowView: View {
    var row: Store.Row
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Circle()
                .fill(row.level >= SecretLevel.secret.rawValue ? Color.orange
                      : (row.level == SecretLevel.internalOnly.rawValue ? Color.secondary : Color.secondary.opacity(0.4)))
                .frame(width: 6, height: 6).padding(.top, 6)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(SecretLevel(rawValue: row.level)?.label ?? "提示")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(row.level >= SecretLevel.secret.rawValue ? .orange : .secondary)
                    Text((row.path as NSString).lastPathComponent)
                        .font(.system(size: 13, weight: .medium))
                        .lineLimit(1)
                    Text(row.kind).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                if !row.ctx.isEmpty {
                    Text(row.ctx).font(.system(size: 12))
                        .foregroundStyle(.secondary).lineLimit(1)
                }
                Text((row.path as NSString).deletingLastPathComponent)
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary).lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }
}

struct MainView: View {
    @ObservedObject var model: Model
    var onScan: () -> Void
    var onStop: () -> Void
    var onReveal: (String) -> Void
    var onOpenSettings: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("保密检查").font(.system(size: 16, weight: .semibold))
                Text(model.scanning
                     ? "正在扫描 \(model.scanned)/\(model.total)"
                     : "上次完成：\(model.lastFinish) · 已索引 \(model.files) 个文件")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    Text("秘密标志 \(model.secret)").foregroundStyle(model.secret > 0 ? .orange : .secondary)
                    Text("内部 \(model.internalCount)")
                    Text("提示 \(model.info)")
                }
                .font(.system(size: 12))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)

            if model.needsFullDisk {
                HStack(spacing: 8) {
                    Text("没有「完全磁盘访问」权限，部分目录没查")
                        .font(.system(size: 12)).foregroundStyle(.orange)
                    Spacer()
                    Button("去授权", action: onOpenSettings).buttonStyle(.link)
                }
                .padding(.horizontal, 16).padding(.bottom, 10)
            }

            Divider()

            if model.rows.isEmpty {
                Text(model.scanning ? "扫描中，命中会实时出现在这里" : "没有发现需要处理的内容")
                    .font(.system(size: 13)).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 180)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(model.rows.enumerated()), id: \.offset) { _, row in
                            RowView(row: row)
                                .contentShape(Rectangle())
                                .onTapGesture { onReveal(row.path) }
                            Divider().padding(.leading, 32)
                        }
                    }
                }
                .frame(minHeight: 240)
            }

            Divider()
            HStack(spacing: 12) {
                if model.scanning {
                    Button("停止", action: onStop)
                } else {
                    Button("开始扫描", action: onScan)
                }
                Spacer()
                Text("只读检查；不联网").font(.system(size: 11)).foregroundStyle(.tertiary)
            }
            .padding(12)
        }
        .frame(width: 560, height: 520)
    }
}

final class WindowController {
    private var window: NSWindow?
    private let model: Model
    private let scanner: Scanner
    private let store: Store

    init(model: Model, scanner: Scanner, store: Store) {
        self.model = model
        self.scanner = scanner
        self.store = store
    }

    func show() {
        if window == nil {
            let view = MainView(model: model,
                                onScan: { [weak self] in self?.scanner.start() },
                                onStop: { [weak self] in self?.scanner.stop() },
                                onReveal: { path in
                                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                                },
                                onOpenSettings: {
                                    let urls = ["x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"]
                                    if let u = urls.compactMap(URL.init(string:)).first {
                                        NSWorkspace.shared.open(u)
                                    }
                                })
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 520),
                             styleMask: [.titled, .closable, .miniaturizable],
                             backing: .buffered, defer: false)
            w.title = "保密检查"
            w.contentView = NSHostingView(rootView: view)
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

// MARK: - AppDelegate

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var store: Store!
    private var scanner: Scanner!
    private let model = Model()
    private var windowCtl: WindowController!
    private var watcher: DirWatcher?

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.accessory)
        store = Store(path: Config.dbPath)
        scanner = Scanner(store: store)
        windowCtl = WindowController(model: model, scanner: scanner, store: store)

        scanner.onChange = { [weak self] in self?.refresh() }
        buildStatusItem()
        refresh()
        scanner.start()

        // 变了就补扫：只补变更的目录，不重扫全盘
        watcher = DirWatcher(paths: Scanner.roots().map(\.path)) { [weak self] changed in
            self?.rescan(paths: changed)
        }
        watcher?.start()
    }

    private func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "保密检查"
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "打开清单", action: #selector(showWindow), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "立即扫描", action: #selector(scanNow), keyEquivalent: "r"))
        menu.addItem(NSMenuItem(title: "停止扫描", action: #selector(stopNow), keyEquivalent: ""))
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "安装开机自启", action: #selector(installAgent), keyEquivalent: ""))
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "退出", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        for item in menu.items { item.target = self }
        statusItem.menu = menu
    }

    private func refresh() {
        let c = store.counts()
        model.secret = c.secret
        model.internalCount = c.internalCount
        model.info = c.info
        model.files = c.files
        model.scanning = scanner.scanning
        model.scanned = scanner.scanned
        model.total = scanner.total
        model.needsFullDisk = scanner.needsFullDisk
        model.rows = store.findings()
        if let d = scanner.lastFinish {
            let f = DateFormatter(); f.dateFormat = "MM-dd HH:mm"
            model.lastFinish = f.string(from: d)
        }
        statusItem.button?.title = c.secret > 0 ? "保密检查 ●\(c.secret)" : "保密检查"
    }

    /// 只补扫变更路径所在的目录，限制在 200 个文件内
    private func rescan(paths: [String]) {
        guard !scanner.scanning else { return }
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            for p in paths.prefix(200) {
                // 文件被删/改名：把记录一起清掉，别留幽灵
                if !FileManager.default.fileExists(atPath: p) {
                    self.store.forget(p)
                    continue
                }
                let dir = (p as NSString).deletingLastPathComponent
                guard let items = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
                for name in items.prefix(50) {
                    let full = dir + "/" + name
                    var isDir: ObjCBool = false
                    guard FileManager.default.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }
                    let u = URL(fileURLWithPath: full)
                    var r = Confidential.Result()
                    Confidential.inspectFileForCLI(u, ocr: true, into: &r)
                    self.store.replaceFindings(path: full, with: r.findings)
                }
            }
            DispatchQueue.main.async { self.refresh() }
        }
    }

    @objc private func showWindow() { windowCtl.show() }
    @objc private func scanNow() { scanner.start() }
    @objc private func stopNow() { scanner.stop() }

    @objc private func installAgent() {
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Label</key><string>com.serena.baomijiancha</string>
          <key>ProgramArguments</key><array><string>\(Config.appPath)/Contents/MacOS/Baomi</string></array>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><false/>
        </dict></plist>
        """
        let dir = NSHomeDirectory() + "/Library/LaunchAgents"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let path = dir + "/com.serena.baomijiancha.plist"
        try? plist.data(using: .utf8)?.write(to: URL(fileURLWithPath: path))
        _ = Shell.run("/bin/launchctl", ["unload", path])
        _ = Shell.run("/bin/launchctl", ["load", path])
        Log.w("agent: 已安装 \(path)")
    }
}

// MARK: - FSEvents：变了才扫

final class DirWatcher {
    private var stream: FSEventStreamRef?
    private let paths: [String]
    private let onChange: ([String]) -> Void
    private var pending: Set<String> = []
    private let lock = NSLock()
    private var timer: Timer?

    init(paths: [String], onChange: @escaping ([String]) -> Void) {
        self.paths = paths
        self.onChange = onChange
    }

    func start() {
        var ctx = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                       retain: nil, release: nil, copyDescription: nil)
        let cb: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<DirWatcher>.fromOpaque(info).takeUnretainedValue()
            // 加了 UseCFTypes，eventPaths 才是 CFArray；否则是 char**，硬转必崩
            let cf = unsafeBitCast(eventPaths, to: CFArray.self)
            let arr = (cf as? [String]) ?? []
            watcher.enqueue(Array(arr.prefix(Int(count))))
        }
        stream = FSEventStreamCreate(nil, cb, &ctx, paths as CFArray,
                                     FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                                     3.0,
                                     UInt32(kFSEventStreamCreateFlagFileEvents
                                            | kFSEventStreamCreateFlagNoDefer
                                            | kFSEventStreamCreateFlagUseCFTypes))
        guard let stream else { return }
        FSEventStreamSetDispatchQueue(stream, DispatchQueue.global(qos: .utility))
        FSEventStreamStart(stream)
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.flush()
        }
    }

    private func enqueue(_ paths: [String]) {
        lock.lock()
        for p in paths { pending.insert(p) }
        lock.unlock()
    }

    private func flush() {
        lock.lock()
        let batch = Array(pending)
        pending.removeAll()
        lock.unlock()
        if !batch.isEmpty { onChange(batch) }
    }
}

// MARK: - 启动

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate

let args = Array(CommandLine.arguments.dropFirst())

// --scan <路径> [--json]：命令行只读体检，便于验证
if args.first == "--scan", let target = args.dropFirst().first {
    let ocr = !args.contains("--no-ocr")
    let r = Confidential.scan(root: URL(fileURLWithPath: target), ocr: ocr)
    if args.contains("--json") { print(r.json) } else { print(r.text()) }
    exit(0)
}

app.run()
