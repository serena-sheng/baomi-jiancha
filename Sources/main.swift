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

// MARK: - 处理结果（落盘，重启后还能撤销/重试）

struct ProcessedItem: Codable, Identifiable {
    var path: String            // 处理后的当前路径（转格式时会变）
    var original: String
    var trash: String?
    var ok: Bool
    var message: String
    var at: Date
    var id: String { original }
}

enum Results {
    static var file: String { Config.supportDir + "/results.json" }

    static func load() -> [ProcessedItem] {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: file)),
              let items = try? JSONDecoder().decode([ProcessedItem].self, from: d) else { return [] }
        return items
    }

    static func save(_ items: [ProcessedItem]) {
        let trimmed = Array(items.suffix(200))
        try? FileManager.default.createDirectory(atPath: Config.supportDir, withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(trimmed) {
            try? d.write(to: URL(fileURLWithPath: file))
        }
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
        var complete = true
        store.beginSweep()
        var files: [URL] = []
        for root in Self.roots() {
            guard !isStopped() else { break }
            guard let en = fm.enumerator(at: root,
                                         includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey],
                                         options: [.skipsHiddenFiles, .skipsPackageDescendants]) else {
                complete = false          // 某个根没走成，这一轮不能拿它做"幽灵清理"的依据
                continue
            }
            for case let u as URL in en {
                if files.count >= Config.maxFiles || isStopped() {
                    complete = false
                    break
                }
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

        if complete {
            store.endSweep()          // 只有完整枚举过才删"这轮没见到"的记录
        } else {
            store.abandonSweep()
            Log.w("scan: 本轮未完整枚举（停止或触顶），保留原索引")
        }
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
    @Published var processingDone = 0
    @Published var processingTotal = 0
    @Published var undoable: Set<String> = []
    @Published var truncated = false
    @Published var processed: [ProcessedItem] = []
    @Published var page = 0
    @Published var pageSize = 50
    @Published var totalHits = 0
    var pageCount: Int { max(1, Int(ceil(Double(totalHits) / Double(pageSize)))) }
}

// MARK: - 界面

/// 与净盘同源的勾选框：14pt 方框，选中时只填强调色 + 一个白色勾
struct JPCheck: View {
    var on: Bool
    var enabled: Bool = true
    var action: () -> Void

    var body: some View {
        Button(action: { if enabled { action() } }) {
            ZStack {
                RoundedRectangle(cornerRadius: 4)
                    .fill(on ? T.accent : .clear)
                    .overlay(
                        RoundedRectangle(cornerRadius: 4)
                            .strokeBorder(on ? Color.clear : T.ink3, lineWidth: 1)
                    )
                if on {
                    Image(systemName: "checkmark")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.white)
                }
            }
            .frame(width: 14, height: 14)
            .opacity(enabled ? 1 : 0.4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(on ? "取消选择" : "选择")
    }
}

struct RowView: View {
    var row: Store.Row
    var selected: Bool
    var status: String?
    var disabled: Bool
    var canUndo: Bool
    var canRetry: Bool
    var onToggle: () -> Void
    var onProcess: () -> Void
    var onReveal: () -> Void
    var onUndo: () -> Void
    var onRetry: () -> Void
    @State private var hovering = false

    private var level: SecretLevel { SecretLevel(rawValue: row.level) ?? .info }
    private var isSecret: Bool { level.isStateSecret }

    var body: some View {
        HStack(alignment: .top, spacing: T.gap) {
            JPCheck(on: selected, enabled: !disabled, action: onToggle)
                .padding(.top, 6)

            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    JPDot(color: isSecret ? T.warn : (level == .internalOnly ? T.ink2 : T.ink3))
                        .offset(y: -1)
                    Text(isSecret ? level.label : (level == .internalOnly ? "内部" : "提示"))
                        .font(.jpC)
                        .foregroundStyle(isSecret ? T.warn : T.ink3)
                    Text((row.path as NSString).lastPathComponent)
                        .font(.jpB)
                        .foregroundStyle(T.ink)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(row.kind + (row.place.isEmpty || row.place == "正文" ? "" : " · \(row.place)"))
                        .font(.jpC)
                        .foregroundStyle(T.ink3)
                        .lineLimit(1)
                    Spacer(minLength: 6)
                    if let status {
                        Text(status)
                            .font(.jpC)
                            .foregroundStyle(status.hasPrefix("没成功") ? T.warn : T.ink3)
                            .lineLimit(1)
                        if canUndo {
                            JPButton(title: "撤销", kind: .ghost, action: onUndo)
                        } else if canRetry {
                            JPButton(title: "重试", kind: .ghost, action: onRetry)
                        }
                    } else {
                        if hovering {
                            Button(action: onReveal) {
                                Image(systemName: "arrow.up.forward.app")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundStyle(T.ink3)
                                    .frame(width: 20, height: 20)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .help("在访达中显示")
                        }
                        JPButton(title: "脱密", kind: .ghost, enabled: !disabled, action: onProcess)
                    }
                }
                if !row.ctx.isEmpty {
                    Text(row.ctx)
                        .font(.jpB)
                        .foregroundStyle(T.ink2)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .padding(.leading, 44)
                }
                Text((row.path as NSString).deletingLastPathComponent)
                    .font(.jpC)
                    .foregroundStyle(T.ink3)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .padding(.leading, 44)
            }
        }
        .padding(.horizontal, T.padH)
        .padding(.vertical, 10)
        .onHover { hovering = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(level.label) \((row.path as NSString).lastPathComponent) \(row.kind)")
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
    var onUndo: (String) -> Void
    var onStopProcessing: () -> Void
    var onPage: (Int) -> Void
    var onSelectPage: () -> Void
    var onRetry: (String) -> Void
    /// 离屏预览时不用 ScrollView（它渲染不出来）
    var preview = false

    private var progress: Double {
        model.total > 0 ? Double(model.scanned) / Double(model.total) : 0
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            JPHairline()
            if !model.processed.isEmpty {
                processedSection
                JPHairline()
            }
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            JPHairline()
            footer
        }
        .frame(minWidth: 520, minHeight: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: 头部

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("保密检查").font(.jpT).foregroundStyle(T.ink)
            Text(statusLine)
                .font(.jpC)
                .foregroundStyle(T.ink2)
            if model.scanning {
                JPBar(value: progress)
                    .padding(.top, 2)
            }
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                JPDot(color: model.secret > 0 ? T.warn : T.ink3).offset(y: -2)
                Text("\(model.secret)").font(.jpT)
                    .foregroundStyle(model.secret > 0 ? T.ink : T.ink3)
                Text("个秘密标志").font(.jpC).foregroundStyle(T.ink2)
                Text("· \(model.internalCount) 内部 · \(model.info) 提示 · 共 \(model.totalHits) 条命中")
                    .font(.jpC).foregroundStyle(T.ink3)
                    .padding(.leading, 4)
                if model.scanning && !model.rows.isEmpty {
                Text("扫描中 · 清单先不更新，新命中结束后一起显示")
                    .font(.jpC).foregroundStyle(T.ink3)
                    .padding(.top, 2)
            }
            if model.needsFullDisk {
                    Text("（不完整）").font(.jpC).foregroundStyle(T.warn)
                }
            }
            .padding(.top, 2)
            if model.scanning && !model.rows.isEmpty {
                Text("扫描中 · 清单先不更新，新命中结束后一起显示")
                    .font(.jpC).foregroundStyle(T.ink3)
                    .padding(.top, 2)
            }
            if model.needsFullDisk {
                HStack(spacing: T.gap) {
                    JPDot(color: T.warn)
                    Text("没有「完全磁盘访问」权限，部分目录没查").font(.jpB).foregroundStyle(T.ink)
                    Button("去授权", action: onOpenSettings)
                        .buttonStyle(.plain)
                        .font(.jpM)
                        .foregroundStyle(T.accent)
                }
                .padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, T.padH)
        .padding(.top, T.padTop)
        .padding(.bottom, 12)
    }

    private var statusLine: String {
        if model.scanning {
            if model.total == 0 { return "正在清点文件，先不显示进度" }
            return "正在扫描 \(model.scanned)/\(model.total)"
        }
        if model.files == 0 { return "还没扫过：首次扫描会读很多文件，请让它跑完" }
        return "已索引 \(model.files) 个文件 · 上次完成 \(model.lastFinish)"
    }

    private func count(label: String, value: Int, tint: Color) -> some View {
        HStack(spacing: 6) {
            JPDot(color: tint)
            Text(label).font(.jpC).foregroundStyle(T.ink2)
            Text("\(value)").font(.jpC).foregroundStyle(T.ink)
        }
    }

    // MARK: 已处理（可撤销/重试）

    private var processedSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: T.gap) {
                Text("本次处理").font(.jpC).foregroundStyle(T.ink3)
                Text("\(model.processed.suffix(5).filter(\.ok).count) 成功 · \(model.processed.suffix(5).filter { !$0.ok }.count) 失败")
                    .font(.jpC).foregroundStyle(T.ink3)
                Spacer()
            }
            .padding(.horizontal, T.padH)
            .padding(.top, 8)
            ForEach(Array(model.processed.suffix(5).reversed())) { item in
                HStack(spacing: T.gap) {
                    JPDot(color: item.ok ? T.ok : T.warn)
                    Text((item.path as NSString).lastPathComponent)
                        .font(.jpB).foregroundStyle(T.ink)
                        .lineLimit(1).truncationMode(.middle)
                    Text(item.ok ? item.message : "没成功：\(item.message)")
                        .font(.jpC).foregroundStyle(item.ok ? T.ink3 : T.warn)
                        .lineLimit(1)
                    Spacer(minLength: 6)
                    if item.ok {
                        JPButton(title: "撤销", kind: .ghost, action: { onUndo(item.path) })
                    } else {
                        JPButton(title: "重试", kind: .ghost, action: { onRetry(item.original) })
                    }
                }
                .padding(.horizontal, T.padH)
                .frame(height: 30)
            }
        }
        .padding(.bottom, 6)
    }

    // MARK: 列表

    @ViewBuilder
    private var content: some View {
        if model.rows.isEmpty {
            VStack(spacing: T.gap) {
                Text(model.scanning ? "扫描中，命中会在结束后列出"
                     : (model.files == 0 ? "还没扫过" : "已扫描 \(model.files) 个文件，没有需要处理的内容"))
                    .font(.jpB).foregroundStyle(T.ink3)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            VStack(spacing: 0) {
                if preview { rowsList } else { ScrollView { rowsList } }
                if model.truncated {
                    Text("只列出前 800 条；全选也只作用于这 800 条")
                        .font(.jpC).foregroundStyle(T.ink3)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, T.padH)
                        .padding(.vertical, 6)
                }
            }
        }
    }

    @ViewBuilder
    private var rowsList: some View {
        LazyVStack(spacing: 0) {
            ForEach(Array(model.rows.enumerated()), id: \.offset) { _, row in
                RowView(row: row,
                        selected: model.selected.contains(row.path),
                        status: model.status[row.path],
                        disabled: model.processing,
                        canUndo: model.undoable.contains(row.path),
                        canRetry: model.status[row.path]?.hasPrefix("没成功") == true,
                        onToggle: { onToggle(row.path) },
                        onProcess: { onProcess([row.path]) },
                        onReveal: { onReveal(row.path) },
                        onUndo: { onUndo(row.path) },
                        onRetry: { onProcess([row.path]) })
                    .contentShape(Rectangle())
                    .onTapGesture { onToggle(row.path) }
                JPHairline()
                    .padding(.leading, T.padH + 22)
                    .padding(.trailing, T.padH)
            }
        }
    }

    // MARK: 底部

    private var footer: some View {
        HStack(spacing: T.block) {
            if model.scanning {
                JPButton(title: "停止", kind: .ghost, action: onStop)
            } else {
                JPButton(title: "开始扫描", kind: .ghost, action: onScan)
                    .keyboardShortcut("r", modifiers: .command)
            }
            JPButton(title: "全选本页", kind: .ghost, enabled: !model.rows.isEmpty) { onSelectPage() }
                .keyboardShortcut("a", modifiers: .command)
            JPButton(title: "清空", kind: .ghost, enabled: !model.selected.isEmpty) { onSelectAll(false) }
            Spacer(minLength: 8)
            if model.processing {
                Text("正在处理 \(model.processingDone)/\(model.processingTotal)")
                    .font(.jpC).foregroundStyle(T.ink2)
                JPButton(title: "中止", kind: .ghost, action: onStopProcessing)
            } else if !model.selected.isEmpty {
                Text("已选 \(model.selected.count) 个").font(.jpC).foregroundStyle(T.ink3)
                JPButton(title: "脱密选中 \(model.selected.count) 个", kind: .primary) {
                    onProcess(Array(model.selected))
                }
            }
            if model.pageCount > 1 && !model.processing {
                HStack(spacing: 4) {
                    Button(action: { onPage(-1) }) {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(model.page > 0 ? T.ink2 : T.ink3)
                            .frame(width: 20, height: 20)
                    }
                    .buttonStyle(.plain)
                    .disabled(model.page == 0 || model.scanning)
                    Text("\(model.page + 1)/\(model.pageCount)")
                        .font(.jpC).foregroundStyle(T.ink2)
                    Button(action: { onPage(1) }) {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(model.page + 1 < model.pageCount ? T.ink2 : T.ink3)
                            .frame(width: 20, height: 20)
                    }
                    .buttonStyle(.plain)
                    .disabled(model.page + 1 >= model.pageCount || model.scanning)
                }
            }
            JPButton(title: "回收目录", kind: .ghost, action: onOpenTrash)
        }
        .padding(.horizontal, T.padH)
        .frame(height: 56)
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
    var onUndo: ((String) -> Void)?
    var onStopProcessing: (() -> Void)?
    var onPage: ((Int) -> Void)?
    var onSelectPage: (() -> Void)?
    var onRetry: ((String) -> Void)?

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
                                onOpenTrash: { [weak self] in self?.onOpenTrash?() },
                                onUndo: { [weak self] p in self?.onUndo?(p) },
                                onStopProcessing: { [weak self] in self?.onStopProcessing?() },
                                onPage: { [weak self] d in self?.onPage?(d) },
                                onSelectPage: { [weak self] in self?.onSelectPage?() },
                                onRetry: { [weak self] p in self?.onRetry?(p) })
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 560),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                             backing: .buffered, defer: false)
            w.title = "保密检查"
            w.titleVisibility = .hidden
            w.titlebarAppearsTransparent = true
            w.isMovableByWindowBackground = true
            w.minSize = NSSize(width: 520, height: 420)
            w.setFrameAutosaveName("BaomiMain")
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
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(NSMenuItem(title: "退出 保密检查",
                                   action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        appItem.submenu = appMenu
        let winItem = NSMenuItem()
        main.addItem(winItem)
        let winMenu = NSMenu(title: "窗口")
        winMenu.addItem(NSMenuItem(title: "关闭", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w"))
        winMenu.addItem(NSMenuItem(title: "最小化", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m"))
        winItem.submenu = winMenu
        NSApp.mainMenu = main
        store = Store(path: Config.dbPath)
        model.processed = Results.load()
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
        windowCtl.onUndo = { [weak self] p in self?.undo(p) }
        windowCtl.onStopProcessing = { [weak self] in self?.cancelProcessing = true }
        windowCtl.onPage = { [weak self] d in self?.goPage(d) }
        windowCtl.onSelectPage = { [weak self] in self?.selectPage() }
        windowCtl.onRetry = { [weak self] p in self?.retry(p) }

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
    private func updateStatusIcon(_ c: (secret: Int, internalCount: Int, info: Int, files: Int)? = nil) {
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
        let k = c ?? store.counts()
        b.title = k.secret > 0 ? " \(k.secret)" : ""
        b.toolTip = scanner.scanning
            ? "正在扫描 \(scanner.scanned)/\(scanner.total)"
            : "保密检查 · \(k.secret) 个秘密标志 · 已索引 \(k.files) 个文件"
    }

    private func rebuildMenu(_ cached: (secret: Int, internalCount: Int, info: Int, files: Int)? = nil) {
        guard let statusItem else { return }
        let c = cached ?? store.counts()
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

    private let readQueue = DispatchQueue(label: "baomi.read", qos: .utility)
    private var refreshing = false

    /// 读库放在后台串行队列：endSweep 删两百万行时，主线程不能跟着等锁
    private func refresh() {
        if refreshing { return }
        refreshing = true
        readQueue.async { [weak self] in
            guard let self else { return }
            let c = self.store.counts()
            let scanning = self.scanner.scanning
            // 扫描中列表不重排：只更新计数与进度，避免用户正在看的行被换走
            let total = self.store.findingsCount()
            let page = min(self.model.page, max(0, Int(ceil(Double(total) / Double(self.model.pageSize))) - 1))
            let rows = scanning ? self.model.rows
                                : self.store.findings(limit: self.model.pageSize,
                                                      offset: page * self.model.pageSize)
            DispatchQueue.main.async {
                self.model.page = page
                self.model.totalHits = total
                self.apply(c: c, rows: rows)
                self.refreshing = false
            }
        }
    }

    private var lastScanRefresh = Date.distantPast

    private func apply(c: (secret: Int, internalCount: Int, info: Int, files: Int), rows: [Store.Row]) {
        model.secret = c.secret
        model.internalCount = c.internalCount
        model.info = c.info
        model.files = c.files
        model.scanning = scanner.scanning
        model.scanned = scanner.scanned
        model.total = scanner.total
        model.needsFullDisk = scanner.needsFullDisk
        model.rows = rows
        model.truncated = false
        if let d = scanner.lastFinish {
            let f = DateFormatter(); f.dateFormat = "MM-dd HH:mm"
            model.lastFinish = f.string(from: d)
        }
        updateStatusIcon(c)
        let sig = "\(scanner.scanning)\(scanner.scanned / 500)\(c.secret)\(c.internalCount)\(c.files)\(idleRescan)\(LoginItem.enabled)"
        if sig != lastMenuSig {
            lastMenuSig = sig
            rebuildMenu(c)
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

    private var rescanBusy = false

    /// 只补扫变更路径所在的目录，限制在 200 个文件内
    private func rescan(paths: [String]) {
        guard !scanner.scanning, !rescanBusy else { return }
        rescanBusy = true
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
                    let v = try? u.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
                    if let old = self.store.fileState(full),
                       old.size == (v?.fileSize ?? 0),
                       abs(old.mtime - (v?.contentModificationDate?.timeIntervalSince1970 ?? 0)) < 1 {
                        continue      // 没变就不重查，省掉重复 OCR
                    }
                    var r = Confidential.Result()
                    Confidential.inspectFileForCLI(u, ocr: true, into: &r)
                    self.store.replaceFindings(path: full, with: r.findings)
                    self.store.markScanned(full,
                                           mtime: v?.contentModificationDate?.timeIntervalSince1970 ?? 0,
                                           size: v?.fileSize ?? 0)
                }
            }
            DispatchQueue.main.async {
                self.rescanBusy = false
                self.refresh()
            }
        }
    }

    private func goPage(_ delta: Int) {
        let target = model.page + delta
        guard target >= 0, target < model.pageCount else { return }
        model.page = target
        refresh()
    }

    private func selectPage() {
        model.selected = Set(model.rows.map(\.path))
    }

    private func toggleSelection(_ path: String) {
        if model.selected.contains(path) { model.selected.remove(path) }
        else { model.selected.insert(path) }
    }

    private var cancelProcessing = false
    private var trashByPath: [String: String] = [:]

    /// 单条或批量：原件进回收目录，副本回原位，然后按复检结果更新清单
    private func declass(_ paths: [String]) {
        guard !paths.isEmpty, !model.processing else { return }
        if paths.count > 1 {
            let names = paths.prefix(3).map { ($0 as NSString).lastPathComponent }.joined(separator: "、")
            let more = paths.count > 3 ? " 等 \(paths.count) 个" : ""
            guard confirm("处理 \(paths.count) 个文件？",
                          "将处理：\(names)\(more)。原件会移入回收目录，处理后可撤销。") else { return }
        }
        model.processing = true
        model.status = [:]
        model.processingDone = 0
        model.processingTotal = paths.count
        cancelProcessing = false
        Log.w("declass: 开始处理 \(paths.count) 个文件")

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var ok = 0, bad = 0
            var handled: [String] = []
            for p in paths {
                if self.cancelProcessing { break }
                handled.append(p)
                let url = URL(fileURLWithPath: p)
                let out = Declass.apply(file: url, ocr: true,
                                        trashDir: URL(fileURLWithPath: Config.trashDir))
                DispatchQueue.main.async {
                    self.model.processingDone += 1
                    if out.ok {
                        self.model.status[p] = "已脱密"
                        self.model.undoable.insert(p)
                        if let t = out.trashedTo { self.trashByPath[p] = t }
                    } else {
                        self.model.status[p] = "没成功：\(out.error ?? "未知")"
                    }
                }
                let finalPath = out.newFile.map { url.deletingLastPathComponent().appendingPathComponent($0).path } ?? p
                DispatchQueue.main.async {
                    let item = ProcessedItem(path: finalPath, original: p, trash: out.trashedTo,
                                             ok: out.ok,
                                             message: out.ok ? out.actions.joined(separator: "、")
                                                             : (out.error ?? "未知"),
                                             at: Date())
                    self.model.processed.removeAll { $0.original == p }
                    self.model.processed.append(item)
                    Results.save(self.model.processed)
                }
                if out.ok {
                    ok += 1
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
                // 只移除真正处理过的；中止后剩下的仍在选中里
                self.model.selected.subtract(handled)
                self.model.processingTotal = 0
                self.refresh()
                Log.w("declass: 完成 ok=\(ok) failed=\(bad)")
                let stopped = self.cancelProcessing
                Notifier.post(title: stopped ? "已中止" : (ok > 0 ? "已脱密 \(ok) 个文件" : "脱密没有完成"),
                              body: stopped
                                ? "已处理 \(ok) 个，剩余的仍选中，可继续"
                                : (ok > 0 ? "原件在回收目录，确认后请删除" + (bad > 0 ? "；\(bad) 个失败" : "")
                                          : "原件都没有改动"))
            }
        }
    }

    private func confirm(_ message: String, _ info: String) -> Bool {
        let a = NSAlert()
        a.messageText = message
        a.informativeText = info
        a.addButton(withTitle: "继续")
        a.addButton(withTitle: "取消")
        NSApp.activate(ignoringOtherApps: true)
        return a.runModal() == .alertFirstButtonReturn
    }

    private func retry(_ original: String) {
        guard !model.processing else { return }
        model.processed.removeAll { $0.original == original }
        Results.save(model.processed)
        declass([original])
    }

    /// 撤销：删掉干净副本，把原件从回收目录搬回来，再重扫一次
    private func undo(_ path: String) {
        guard let item = model.processed.first(where: { $0.path == path || $0.original == path }),
              let trash = item.trash,
              FileManager.default.fileExists(atPath: trash) else { return }
        guard confirm("撤销这次脱密？", "会删掉脱密后的副本，把原件移回原位置并重新检查。") else { return }
        let url = URL(fileURLWithPath: item.path)
        let original = URL(fileURLWithPath: item.original)
        do {
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.removeItem(at: url)
            }
            try Declass.transfer(URL(fileURLWithPath: trash), original)
            model.status[item.original] = "已还原"
            model.undoable.remove(path)
            trashByPath[path] = nil
            model.processed.removeAll { $0.path == path || $0.original == path }
            Results.save(model.processed)
            store.forget(item.original)          // 指纹要清掉，不然重扫会跳过
            if item.path != item.original { store.forget(item.path) }
            Log.w("undo: 已还原 \(item.original)")
            rescan(paths: [item.original])
        } catch {
            model.status[path] = "没成功：还原失败"
            Log.w("undo failed \(path): \(error.localizedDescription)")
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

    deinit { stop() }

    func stop() {
        timer?.invalidate(); timer = nil
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }

    func start() {
        guard stream == nil else { return }
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

// --preview <目录>：离屏渲染主窗口的几种状态，用于视觉评审（不读真实文件）
if args.first == "--preview" {
    // 预览只是出图：摘掉 delegate，别让它真的去扫盘、写库
    app.delegate = nil
    let dir = args.dropFirst().first ?? "/tmp/baomi-preview"
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    app.setActivationPolicy(.accessory)
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
        func base() -> Model {
            let m = Model()
            m.files = 25560
            m.lastFinish = "10-23 21:40"
            m.totalHits = 37232
            m.internalCount = 81
            m.info = 37132
            m.page = 0
            m.pageSize = 50
            return m
        }
        func rows() -> [Store.Row] {
            [
                .init(path: "/Users/serena/Desktop/绝密材料.txt", kind: "密级标志", level: 4,
                      place: "正文", value: "绝密", note: "",
                      ctx: "「绝密」★ 保密期限 30 年 本文件仅限内部传阅"),
                .init(path: "/Users/serena/Desktop/扫描件-机密.pdf", kind: "密级标志", level: 3,
                      place: "1 页·OCR", value: "机密", note: "",
                      ctx: "「机密」★ 保密期限 10 年 关于第三季度经营情况的通报"),
                .init(path: "/Users/serena/Desktop/报告.docx", kind: "修订痕迹", level: 1,
                      place: "正文", value: "修订记录", note: "",
                      ctx: "文档被改过 2 次，历史内容可能仍在"),
                .init(path: "/Users/serena/Desktop/照片.jpg", kind: "照片位置", level: 0,
                      place: "GPS", value: "拍摄位置", note: "",
                      ctx: "照片会暴露拍摄地点"),
            ]
        }

        var cases: [(String, Model)] = []

        let scanning = base()
        scanning.scanning = true; scanning.scanned = 25560; scanning.total = 91219
        scanning.secret = 3
        scanning.rows = rows(); scanning.selected = ["/Users/serena/Desktop/报告.docx"]
        cases.append(("scanning", scanning))

        let idle = base()
        idle.secret = 3
        idle.rows = rows()
        cases.append(("idle", idle))

        let empty = base()
        cases.append(("empty", empty))

        let processing = base()
        processing.secret = 1; processing.rows = rows().prefix(2).map { $0 }
        processing.processing = true
        processing.processingDone = 2
        processing.processingTotal = 12
        processing.status = ["/Users/serena/Desktop/绝密材料.txt": "已脱密"]
        processing.processed = [
            ProcessedItem(path: "/Users/serena/Desktop/绝密材料.txt",
                          original: "/Users/serena/Desktop/绝密材料.txt",
                          trash: "/tmp/x", ok: true,
                          message: "遮盖命中内容、删除密级标志行", at: Date()),
            ProcessedItem(path: "/Users/serena/Desktop/扫描件-机密.pdf",
                          original: "/Users/serena/Desktop/扫描件-机密.pdf",
                          trash: nil, ok: false,
                          message: "PDF 已加密，读不了内容", at: Date()),
        ]
        cases.append(("processing", processing))

        let noPermission = base()
        noPermission.needsFullDisk = true; noPermission.rows = rows()
        cases.append(("noperm", noPermission))

        for (name, m) in cases {
            for scheme in [ColorScheme.light, .dark] {
                let view = MainView(model: m, onScan: {}, onStop: {}, onReveal: { _ in },
                                    onOpenSettings: {}, onToggle: { _ in }, onProcess: { _ in },
                                    onSelectAll: { _ in }, onOpenTrash: {},
                                    onUndo: { _ in }, onStopProcessing: {},
                                    onPage: { _ in }, onSelectPage: {}, onRetry: { _ in },
                                    preview: true)
                    .frame(width: 600, height: 560)
                    .environment(\.colorScheme, scheme)
                let r = ImageRenderer(content: view)
                r.scale = 2
                r.isOpaque = true
                if let cg = r.cgImage {
                    let rep = NSBitmapImageRep(cgImage: cg)
                    let file = name + (scheme == .dark ? "-dark" : "") + ".png"
                    try? rep.representation(using: .png, properties: [:])?
                        .write(to: URL(fileURLWithPath: dir + "/" + file))
                }
            }
        }
        print("wrote \(cases.count * 2) previews to \(dir)")
        exit(0)
    }
    app.run()
}

app.run()
