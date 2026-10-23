// 保密检查 — macOS 常驻后台全盘扫描
// 只读检查：找密级标志、内部痕迹、证件号、文档属性、扫描件里的字。
// 本地、离线、不写内容进日志；结果存本机 SQLite。
import Cocoa
import SwiftUI
import CoreServices
import UserNotifications
import IOKit

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

// MARK: - 通知

enum Notifier {
    static func post(title: String, body: String) {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        c.sound = nil
        if #available(macOS 12.0, *) { c.interruptionLevel = .passive }
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil)
        UNUserNotificationCenter.current().add(req, withCompletionHandler: nil)
    }
}

// MARK: - 配置

enum Config {
    static let supportDir = NSHomeDirectory() + "/Library/Application Support/保密检查"
    static let dbPath = supportDir + "/index.db"
    static let trashDir = supportDir + "/trash"
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

// MARK: - 开机自启（LaunchAgent）

enum LoginItem {
    static let label = "com.serena.baomijiancha"
    static var path: String { NSHomeDirectory() + "/Library/LaunchAgents/\(label).plist" }
    static var enabled: Bool { FileManager.default.fileExists(atPath: path) }

    static func install() {
        let exe = Bundle.main.executablePath ?? Config.appPath + "/Contents/MacOS/Baomi"
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Label</key><string>\(label)</string>
          <key>ProgramArguments</key><array><string>\(exe)</string></array>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><false/>
          <key>ProcessType</key><string>Interactive</string>
        </dict></plist>
        """
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try? plist.data(using: .utf8)?.write(to: URL(fileURLWithPath: path))
        _ = Shell.run("/bin/launchctl", ["unload", path])
        _ = Shell.run("/bin/launchctl", ["load", path])
        Log.w("login: 已开启开机自启 \(path)")
    }

    static func remove() {
        _ = Shell.run("/bin/launchctl", ["unload", path])
        try? FileManager.default.removeItem(atPath: path)
        Log.w("login: 已关闭开机自启")
    }
}

/// 系统空闲了多少秒（任意输入都算）
func systemIdleSeconds() -> Double {
    let anyInput = CGEventType(rawValue: ~0)!
    return CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: anyInput)
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
    private(set) var lastStart: Date?
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
        lastStart = Date()
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
    @Published var selected: Set<String> = []
    @Published var processing = false
    @Published var status: [String: String] = [:]
}

// MARK: - 界面

struct RowView: View {
    var row: Store.Row
    var selected: Bool
    var status: String?
    var disabled: Bool
    var onToggle: () -> Void
    var onProcess: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Toggle("", isOn: Binding(get: { selected }, set: { _ in onToggle() }))
                .toggleStyle(.checkbox)
                .labelsHidden()
                .padding(.top, 1)
                .disabled(disabled)
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
            Spacer(minLength: 8)
            if let status {
                Text(status)
                    .font(.system(size: 12))
                    .foregroundStyle(status.hasPrefix("失败") ? .orange : .secondary)
                    .lineLimit(1)
            } else {
                Button("脱密", action: onProcess)
                    .buttonStyle(.link)
                    .font(.system(size: 12))
                    .disabled(disabled)
            }
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
    var onToggle: (String) -> Void
    var onProcess: ([String]) -> Void
    var onSelectAll: (Bool) -> Void
    var onOpenTrash: () -> Void

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
                            RowView(row: row,
                                    selected: model.selected.contains(row.path),
                                    status: model.status[row.path],
                                    disabled: model.processing,
                                    onToggle: { onToggle(row.path) },
                                    onProcess: { onProcess([row.path]) })
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
                Button("全选") { onSelectAll(true) }
                    .disabled(model.rows.isEmpty)
                Button("清空") { onSelectAll(false) }
                    .disabled(model.selected.isEmpty)
                Spacer()
                if model.processing {
                    Text("正在处理…").font(.system(size: 12)).foregroundStyle(.secondary)
                } else if !model.selected.isEmpty {
                    Button("脱密选中 \(model.selected.count) 个") { onProcess(Array(model.selected)) }
                }
                Button("回收目录", action: onOpenTrash)
                    .buttonStyle(.link)
                    .font(.system(size: 12))
                Text("不联网").font(.system(size: 11)).foregroundStyle(.tertiary)
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

    var onToggle: ((String) -> Void)?
    var onProcess: (([String]) -> Void)?
    var onSelectAll: ((Bool) -> Void)?
    var onOpenTrash: (() -> Void)?

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
                                },
                                onToggle: { [weak self] p in self?.onToggle?(p) },
                                onProcess: { [weak self] paths in self?.onProcess?(paths) },
                                onSelectAll: { [weak self] on in self?.onSelectAll?(on) },
                                onOpenTrash: { [weak self] in self?.onOpenTrash?() })
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
    private var idleTimer: Timer?
    private var lastMenuSig = ""

    /// 空闲 2 小时后自动重扫
    private var idleRescan: Bool {
        get { UserDefaults.standard.object(forKey: "idleRescan") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "idleRescan"); rebuildMenu() }
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        Log.w("app: 启动，roots=\(Scanner.roots().map(\.path).joined(separator: ","))")
        NSApp.setActivationPolicy(.accessory)
        store = Store(path: Config.dbPath)
        scanner = Scanner(store: store)
        windowCtl = WindowController(model: model, scanner: scanner, store: store)
        windowCtl.onToggle = { [weak self] p in self?.toggleSelection(p) }
        windowCtl.onProcess = { [weak self] paths in self?.declass(paths) }
        windowCtl.onSelectAll = { [weak self] on in
            guard let self else { return }
            self.model.selected = on ? Set(self.model.rows.map(\.path)) : []
        }
        windowCtl.onOpenTrash = {
            NSWorkspace.shared.open(URL(fileURLWithPath: Config.trashDir))
        }

        scanner.onChange = { [weak self] in self?.refresh() }
        buildStatusItem()
        refresh()
        Log.w("app: 开始首次扫描")
        scanner.start()

        // 变了就补扫：只补变更的目录，不重扫全盘
        watcher = DirWatcher(paths: Scanner.roots().map(\.path)) { [weak self] changed in
            self?.rescan(paths: changed)
        }
        watcher?.start()

        // 第一次运行就装上开机自启，之后交给菜单里的开关
        if !LoginItem.enabled && UserDefaults.standard.object(forKey: "loginInstalled") == nil {
            LoginItem.install()
            UserDefaults.standard.set(true, forKey: "loginInstalled")
        }

        idleTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.checkIdleRescan()
        }
    }

    private func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let b = statusItem.button {
            b.imagePosition = .imageLeading
            b.imageScaling = .scaleProportionallyDown
        }
        rebuildMenu()
    }

    /// 菜单栏图标就是状态：扫的时候是实心盾，闲着是勾盾，停了是暂停。
    private func updateStatusIcon() {
        guard let b = statusItem.button else { return }
        let symbol: String
        if scanner.scanning { symbol = "shield.lefthalf.filled" }
        else if let last = scanner.lastFinish, Date().timeIntervalSince(last) < 3600 * 24 { symbol = "checkmark.shield" }
        else { symbol = "shield" }
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .regular)
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "保密检查")?
            .withSymbolConfiguration(cfg)
        img?.isTemplate = true
        b.image = img
        let c = store.counts()
        b.title = c.secret > 0 ? " \(c.secret)" : ""
        b.toolTip = scanner.scanning
            ? "正在扫描 \(scanner.scanned)/\(scanner.total)"
            : "保密检查 · 已索引 \(c.files) 个文件"
    }

    private func rebuildMenu() {
        guard let statusItem else { return }
        let c = store.counts()
        let menu = NSMenu()

        let state = NSMenuItem(title: scanner.scanning
                               ? "正在扫描 \(scanner.scanned)/\(scanner.total)"
                               : "空闲 · 已索引 \(c.files) 个文件", action: nil, keyEquivalent: "")
        state.isEnabled = false
        menu.addItem(state)

        let summary = NSMenuItem(title: "秘密标志 \(c.secret) · 内部 \(c.internalCount) · 提示 \(c.info)",
                                 action: nil, keyEquivalent: "")
        summary.isEnabled = false
        menu.addItem(summary)

        if let last = scanner.lastFinish {
            let f = DateFormatter(); f.dateFormat = "MM-dd HH:mm"
            let done = NSMenuItem(title: "上次完成 \(f.string(from: last))", action: nil, keyEquivalent: "")
            done.isEnabled = false
            menu.addItem(done)
        }
        menu.addItem(.separator())

        menu.addItem(NSMenuItem(title: "打开清单", action: #selector(showWindow), keyEquivalent: ""))
        if scanner.scanning {
            menu.addItem(NSMenuItem(title: "停止扫描", action: #selector(stopNow), keyEquivalent: ""))
        } else {
            menu.addItem(NSMenuItem(title: "立即扫描", action: #selector(scanNow), keyEquivalent: "r"))
        }
        menu.addItem(.separator())

        let idle = NSMenuItem(title: "空闲 2 小时后自动重扫", action: #selector(toggleIdle), keyEquivalent: "")
        idle.state = idleRescan ? .on : .off
        menu.addItem(idle)

        let login = NSMenuItem(title: "开机自启", action: #selector(toggleLogin), keyEquivalent: "")
        login.state = LoginItem.enabled ? .on : .off
        menu.addItem(login)

        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "退出", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        for item in menu.items where item.action != nil { item.target = self }
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
        updateStatusIcon()
        // 菜单重建有成本，只在状态变化时做
        let sig = "\(scanner.scanning)\(scanner.scanned / 500)\(c.secret)\(c.internalCount)\(c.files)\(idleRescan)\(LoginItem.enabled)"
        if sig != lastMenuSig {
            lastMenuSig = sig
            rebuildMenu()
        }
    }

    private func checkIdleRescan() {
        guard idleRescan, !scanner.scanning else { return }
        let limit = Double(ProcessInfo.processInfo.environment["BAOMI_IDLE_SECONDS"] ?? "") ?? 7200
        let idle = systemIdleSeconds()
        let since = Date().timeIntervalSince(scanner.lastStart ?? .distantPast)
        if ProcessInfo.processInfo.environment["BAOMI_IDLE_SECONDS"] != nil {
            Log.w(String(format: "idle-check: idle=%.1f since=%.1f limit=%.1f", idle, since, limit))
        }
        guard idle >= limit, since >= limit else { return }
        Log.w(String(format: "idle: 空闲 %.0f 分钟，重新开扫", idle / 60))
        scanner.start()
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

    private func toggleSelection(_ path: String) {
        if model.selected.contains(path) { model.selected.remove(path) }
        else { model.selected.insert(path) }
    }

    /// 单条或批量：原件进回收目录，副本回原位，然后按复检结果更新清单
    private func declass(_ paths: [String]) {
        guard !paths.isEmpty, !model.processing else { return }
        model.processing = true
        model.status = [:]
        Log.w("declass: 开始处理 \(paths.count) 个文件")

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var ok = 0, bad = 0
            for p in paths {
                let url = URL(fileURLWithPath: p)
                let out = Declass.apply(file: url, ocr: true,
                                        trashDir: URL(fileURLWithPath: Config.trashDir))
                DispatchQueue.main.async {
                    self.model.status[p] = out.ok ? "已脱密" : "失败：\(out.error ?? "未知")"
                }
                if out.ok {
                    ok += 1
                    // 复检过了就按新文件重扫一遍，把这一行的命中更新掉
                    let finalPath = out.newFile.map { url.deletingLastPathComponent().appendingPathComponent($0).path } ?? p
                    var r = Confidential.Result()
                    Confidential.inspectFileForCLI(URL(fileURLWithPath: finalPath), ocr: true, into: &r)
                    self.store.replaceFindings(path: finalPath, with: r.findings)
                    if finalPath != p { self.store.forget(p) }
                } else {
                    bad += 1
                    Log.w("declass failed \(p): \(out.error ?? "-")")
                }
            }
            DispatchQueue.main.async {
                self.model.processing = false
                self.model.selected = []
                self.refresh()
                Log.w("declass: 完成 ok=\(ok) failed=\(bad)")
                Notifier.post(title: ok > 0 ? "已脱密 \(ok) 个文件" : "脱密没有完成",
                              body: ok > 0
                                ? "原件在回收目录，确认后请删除" + (bad > 0 ? "；\(bad) 个失败" : "")
                                : "原件都没有改动")
            }
        }
    }

    @objc private func showWindow() { windowCtl.show() }
    @objc private func scanNow() { scanner.start() }
    @objc private func stopNow() { scanner.stop() }

    @objc private func toggleIdle() { idleRescan.toggle() }

    @objc private func toggleLogin() {
        if LoginItem.enabled { LoginItem.remove() } else { LoginItem.install() }
        rebuildMenu()
    }

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

// 单实例：开机自启与手动打开同时发生时，只留一个进程，避免两份扫描抢磁盘
if CommandLine.arguments.count <= 1,
   let bid = Bundle.main.bundleIdentifier,
   NSRunningApplication.runningApplications(withBundleIdentifier: bid).count > 1 {
    exit(0)
}

let delegate = AppDelegate()
app.delegate = delegate

let args = Array(CommandLine.arguments.dropFirst())

// --scan <路径> [--json]：命令行只读体检，便于验证
if args.first == "--scan", let target = args.dropFirst().first {
    let ocr = !args.contains("--no-ocr")
    let url = URL(fileURLWithPath: target)
    var isDir: ObjCBool = false
    FileManager.default.fileExists(atPath: target, isDirectory: &isDir)
    var r = Confidential.Result()
    if isDir.boolValue {
        r = Confidential.scan(root: url, ocr: ocr)
    } else {
        Confidential.inspectFileForCLI(url, ocr: ocr, into: &r)
        r.seconds = 0
    }
    if args.contains("--json") { print(r.json) } else { print(r.text()) }
    exit(0)
}

// --process <路径>：走和界面同一条脱密管线（测试/批处理用）
if args.first == "--process", let target = args.dropFirst().first {
    let root = URL(fileURLWithPath: target)
    let conf = Confidential.scan(root: root, ocr: true)
    var files: [String] = []
    for f in conf.findings where f.kind != .unscannable {
        if !files.contains(f.file) { files.append(f.file) }
    }
    var ok = 0, bad = 0
    for rel in files {
        let url = root.appendingPathComponent(rel)
        let out = Declass.apply(file: url, ocr: true,
                                trashDir: URL(fileURLWithPath: Config.trashDir))
        if out.ok {
            ok += 1
            print("✓ \(rel)  \(out.actions.joined(separator: "、"))")
        } else {
            bad += 1
            print("✗ \(rel)  \(out.error ?? "-")")
        }
    }
    print("完成：\(ok) 个已脱密，\(bad) 个失败；原件在 \(Config.trashDir)")
    exit(bad == 0 ? 0 : 1)
}

app.run()
