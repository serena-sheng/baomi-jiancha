// 从净盘抽出的检查引擎：密级判定、OCR、CFB/OFD、脱密。
// 只依赖 Foundation / PDFKit / ImageIO / Vision / 系统的 unzip、zip。
import Foundation
import PDFKit
import ImageIO
import Vision

/// 字节数的统一格式（原 Volume.fmt）
enum Fmt {
    static func bytes(_ b: Int64) -> String {
        if b < 1024 { return "\(b) 字节" }
        let f = ByteCountFormatter()
        f.countStyle = .file
        f.allowedUnits = b < 1024 * 1024 ? [.useKB] : [.useMB, .useGB]
        return f.string(fromByteCount: b)
    }
}

enum Shell {
    /// 外部命令一律带超时；stderr 直接丢掉，否则子进程写满管道会和我们互锁
    @discardableResult
    static func run(_ path: String, _ args: [String], cwd: String? = nil,
                    timeout: TimeInterval = 15) -> (out: String, ok: Bool) {
        guard FileManager.default.isExecutableFile(atPath: path) else { return ("", false) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        if let cwd { p.currentDirectoryURL = URL(fileURLWithPath: cwd) }
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return ("", false) }

        var data = Data()
        let readDone = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            data = out.fileHandleForReading.readDataToEndOfFile()
            readDone.signal()
        }
        let waitDone = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in waitDone.signal() }

        if waitDone.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate()
            if waitDone.wait(timeout: .now() + 2) == .timedOut {
                kill(p.processIdentifier, SIGKILL)
                _ = waitDone.wait(timeout: .now() + 2)
            }
            _ = readDone.wait(timeout: .now() + 2)
            Log.w("shell: 超时 \(path) \(args.prefix(2).joined(separator: " "))")
            return ("", false)
        }
        _ = readDone.wait(timeout: .now() + 2)
        return (String(decoding: data, as: UTF8.self), p.terminationStatus == 0)
    }
}

enum SecretLevel: Int, Comparable {
    case info = 0          // 提示：只剩「无法检查」这类覆盖说明，不进清单、不参与脱密
    case workSecret = 1    // 工作秘密：不是国家秘密，但仍然按秘密对待
    case secret = 2        // 秘密★
    case confidential = 3  // 机密★
    case topSecret = 4     // 绝密★

    var label: String {
        switch self {
        case .topSecret: return "绝密"
        case .confidential: return "机密"
        case .secret: return "秘密"
        case .workSecret: return "工作秘密"
        case .info: return "提示"
        }
    }
    var isStateSecret: Bool { self.rawValue >= SecretLevel.secret.rawValue }
    /// 口径：只有国家秘密与工作秘密进清单、参与脱密；内部资料与个人信息不再报
    var isReportable: Bool { self.rawValue >= SecretLevel.workSecret.rawValue }

    static func < (a: SecretLevel, b: SecretLevel) -> Bool { a.rawValue < b.rawValue }
}

enum ConfKind: String {
    case classification = "密级标志"
    case idCard         = "身份证号"
    case bankCard       = "银行卡号"
    case phone          = "手机号"
    case uscc           = "统一社会信用代码"
    case author         = "文档属性"
    case revision       = "修订痕迹"
    case comment        = "批注"
    case embed          = "嵌入内容"
    case exif           = "照片位置"
    case unscannable    = "无法检查"
}

struct ConfFinding {
    var kind: ConfKind
    var file: String
    var place: String
    var value: String
    var note: String
    var level: SecretLevel
    var viaOCR = false
    /// 命中处的一小段上下文：让人一眼认出这是哪份材料、哪句话
    var context: String = ""
}

// MARK: - 本地 OCR（系统 Vision，设备端）

enum OCR {
    static var languages: [String] { ["zh-Hans", "en-US"] }

    static func text(from cg: CGImage, fast: Bool = false) -> String {
        let req = VNRecognizeTextRequest()
        req.recognitionLevel = fast ? .fast : .accurate
        req.recognitionLanguages = languages
        req.usesLanguageCorrection = true
        let handler = VNImageRequestHandler(cgImage: cg, options: [:])
        do { try handler.perform([req]) } catch { return "" }
        let lines = (req.results ?? []).compactMap { $0.topCandidates(1).first?.string }
        return lines.joined(separator: "\n")
    }

    /// PDF 单页栅格化后识别：200dpi 对中文印刷体够用，再高只是变慢
    static func text(from page: PDFPage, dpi: CGFloat = 150) -> String {
        let rect = page.bounds(for: .mediaBox)
        let scale = dpi / 72.0
        let w = Int(rect.width * scale), h = Int(rect.height * scale)
        guard w > 0, h > 0, w * h <= 40_000_000 else { return "" }
        guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue) else { return "" }
        ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
        ctx.scaleBy(x: scale, y: scale)
        page.draw(with: .mediaBox, to: ctx)
        guard let cg = ctx.makeImage() else { return "" }
        return text(from: cg)
    }

    struct Hit {
        var rect: CGRect          // Vision 归一化坐标（原点左下）
        var text: String
        var level: SecretLevel
        var kind: ConfKind
    }

    /// 带位置的一遍识别：脱密时按这个矩形盖白块，而不是赌"整页重来"
    static func hits(in cg: CGImage) -> [Hit] {
        let req = VNRecognizeTextRequest()
        req.recognitionLevel = .accurate
        req.recognitionLanguages = languages
        req.usesLanguageCorrection = true
        let handler = VNImageRequestHandler(cgImage: cg, options: [:])
        do { try handler.perform([req]) } catch { return [] }
        var out: [Hit] = []
        for obs in req.results ?? [] {
            guard let cand = obs.topCandidates(1).first else { continue }
            let line = cand.string
            let ns = line as NSString

            // 只认密级标志：图片里的证件号、手机号不再单独报，也不再遮盖
            if let (level, _) = Confidential.classification(in: line), level.isReportable,
               let range = Range(NSRange(location: 0, length: ns.length), in: line),
               let box = try? cand.boundingBox(for: range) {
                out.append(Hit(rect: box.boundingBox, text: line, level: level, kind: .classification))
            }
        }
        return out
    }

    static func text(fromImageAt url: URL, maxPixel: CGFloat = 2400) -> String {
        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil),
              let img = CGImageSourceCreateImageAtIndex(src, 0, nil) else { return "" }
        let longest = CGFloat(max(img.width, img.height))
        if longest <= maxPixel { return text(from: img) }
        let scale = maxPixel / longest
        let w = Int(CGFloat(img.width) * scale), h = Int(CGFloat(img.height) * scale)
        guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue),
              let scaled = { () -> CGImage? in
                  ctx.interpolationQuality = .high
                  ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
                  return ctx.makeImage()
              }() else { return "" }
        return text(from: scaled)
    }
}

// MARK: - OLE 复合文档（.wps / .et / .dps / .doc / .xls / .ppt）
//
// WPS 的旧格式不是 zip，是 OLE 复合文档（CFB，魔数 D0CF11E0）。解不开它就既查不了也脱不了，
// 所以这里只做三件能保证正确的事：认格式、读元数据、按字节找可见文字。
// 真正的正文改写不在这里做——二进制格式改长度会把文件写坏。

enum CFB {
    struct Entry {
        var name: String
        var type: UInt8          // 1 storage, 2 stream, 5 root
        var start: UInt32
        var size: UInt64
    }

    static func magic(_ d: Data) -> Bool {
        guard d.count > 512 else { return false }
        return Array(d.prefix(8)) == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
    }

    private static func u16(_ d: Data, _ i: Int) -> UInt16 {
        guard i + 2 <= d.count else { return 0 }
        return UInt16(d[i]) | (UInt16(d[i + 1]) << 8)
    }
    private static func u32(_ d: Data, _ i: Int) -> UInt32 {
        guard i + 4 <= d.count else { return 0 }
        return UInt32(d[i]) | (UInt32(d[i + 1]) << 8) | (UInt32(d[i + 2]) << 16) | (UInt32(d[i + 3]) << 24)
    }

    private static func sector(_ d: Data, _ n: UInt32, _ size: Int) -> Data {
        let start = (Int(n) + 1) * size
        guard start >= 0, start + size <= d.count else { return Data() }
        return d.subdata(in: start..<(start + size))
    }

    /// 读出目录里的所有条目（名字 + 起始扇区 + 大小）
    static func entries(_ d: Data) -> [Entry] {
        guard magic(d) else { return [] }
        let ss = 1 << Int(u16(d, 30))
        let dirStart = u32(d, 48)
        var fatSectors: [UInt32] = []
        for i in 0..<109 {
            let v = u32(d, 76 + i * 4)
            if v != 0xFFFFFFFF { fatSectors.append(v) }
        }
        let difatStart = u32(d, 68)
        if difatStart != 0xFFFFFFFF && difatStart != 0xFFFFFFFE {
            var s = difatStart
            var guard_ = 0
            while s != 0xFFFFFFFE && guard_ < 1000 {
                let blk = sector(d, s, ss)
                guard blk.count == ss else { break }
                let per = ss / 4 - 1
                for i in 0..<per {
                    let v = u32(blk, i * 4)
                    if v != 0xFFFFFFFF { fatSectors.append(v) }
                }
                s = u32(blk, per * 4)
                guard_ += 1
            }
        }

        var fat: [UInt32] = []
        for fs in fatSectors {
            let blk = sector(d, fs, ss)
            guard blk.count == ss else { continue }
            for i in 0..<(ss / 4) { fat.append(u32(blk, i * 4)) }
        }
        guard !fat.isEmpty else { return [] }

        var out: [Entry] = []
        var cur = dirStart
        var hops = 0
        while cur != 0xFFFFFFFE && cur != 0xFFFFFFFF && Int(cur) < fat.count && hops < 4096 {
            let blk = sector(d, cur, ss)
            guard blk.count == ss else { break }
            for off in stride(from: 0, to: ss, by: 128) {
                let nameLen = Int(u16(blk, off + 64))
                let type = blk[off + 66]
                guard type == 1 || type == 2 || type == 5, nameLen >= 2, nameLen <= 64 else { continue }
                let nameData = blk.subdata(in: (off + 0)..<(off + max(0, nameLen - 2)))
                let name = String(data: nameData, encoding: .utf16LittleEndian) ?? ""
                out.append(Entry(name: name, type: type,
                                 start: u32(blk, off + 116),
                                 size: UInt64(u32(blk, off + 120))))
            }
            cur = fat[Int(cur)]
            hops += 1
        }
        return out
    }

    /// 流内容（含 mini stream）
    static func stream(_ d: Data, name: String) -> Data? {
        guard magic(d) else { return nil }
        let ss = 1 << Int(u16(d, 30))
        let miniSS = 1 << Int(u16(d, 32))
        let miniCut = u32(d, 56)
        let entries = entries(d)
        guard let e = entries.first(where: { $0.type == 2 && $0.name == name }) else { return nil }

        // FAT
        var fatSectors: [UInt32] = []
        for i in 0..<109 {
            let v = u32(d, 76 + i * 4)
            if v != 0xFFFFFFFF { fatSectors.append(v) }
        }
        var fat: [UInt32] = []
        for fs in fatSectors {
            let blk = sector(d, fs, ss)
            guard blk.count == ss else { continue }
            for i in 0..<(ss / 4) { fat.append(u32(blk, i * 4)) }
        }

        func chain(_ start: UInt32, _ limit: Int) -> Data {
            var out = Data()
            var cur = start
            var hops = 0
            while cur != 0xFFFFFFFE && cur != 0xFFFFFFFF && Int(cur) < fat.count && hops < limit {
                out.append(sector(d, cur, ss))
                cur = fat[Int(cur)]
                hops += 1
            }
            return out
        }

        if e.size >= UInt64(miniCut) {
            let data = chain(e.start, Int(e.size / UInt64(ss)) + 2)
            return data.prefix(Int(min(e.size, UInt64(data.count))))
        }

        // mini stream：根条目里的小流容器 + miniFAT
        guard let root = entries.first(where: { $0.type == 5 }) else { return nil }
        let miniData = chain(root.start, 4096)
        let miniFatStart = u32(d, 60)
        let miniFat = chain(miniFatStart, 4096)
        var out = Data()
        var cur = e.start
        var hops = 0
        while cur != 0xFFFFFFFE && cur != 0xFFFFFFFF && hops < 4096 {
            let off = Int(cur) * miniSS
            guard off + miniSS <= miniData.count else { break }
            out.append(miniData.subdata(in: off..<(off + miniSS)))
            let idx = Int(cur) * 4
            guard idx + 4 <= miniFat.count else { break }
            cur = u32(miniFat, idx)
            hops += 1
        }
        return out.prefix(Int(min(e.size, UInt64(out.count))))
    }

    static func entryNames(_ d: Data) -> [String] {
        entries(d).filter { $0.type == 2 }.map(\.name)
    }
}

// MARK: - 属性集（SummaryInformation 里的作者、最后保存人、修订次数）

enum PropertySet {
    struct Info {
        var title: String?
        var author: String?
        var lastSavedBy: String?
        var revision: String?
        var company: String?
        var lastPrinted: String?
    }

    /// 只读 LPSTR / LPWSTR / FILETIME；其余类型跳过，不猜
    static func parse(_ data: Data) -> Info {
        var info = Info()
        guard data.count > 48 else { return info }
        func u16(_ i: Int) -> UInt16 {
            guard i + 2 <= data.count else { return 0 }
            return UInt16(data[i]) | (UInt16(data[i + 1]) << 8)
        }
        func u32(_ i: Int) -> UInt32 {
            guard i + 4 <= data.count else { return 0 }
            return UInt32(data[i]) | (UInt32(data[i + 1]) << 8) | (UInt32(data[i + 2]) << 16) | (UInt32(data[i + 3]) << 24)
        }
        let numSets = Int(u32(24))
        guard numSets >= 1, 28 + 20 <= data.count else { return info }
        let sectionOff = Int(u32(28 + 16))          // 第一组属性集的段偏移
        guard sectionOff + 8 <= data.count else { return info }
        let count = Int(u32(sectionOff + 4))
        guard count > 0, count < 64 else { return info }
        for i in 0..<count {
            let entry = sectionOff + 8 + i * 8       // 每条：propid(4) + 值偏移(4)
            guard entry + 8 <= data.count else { continue }
            let id = u32(entry)
            let off = sectionOff + Int(u32(entry + 4))
            guard off + 4 <= data.count else { continue }
            let type = u16(off)
            var value = ""
            if type == 0x1E {           // VT_LPSTR
                let len = Int(u32(off + 4))
                guard len > 0, off + 8 + len <= data.count else { continue }
                let raw = data.subdata(in: (off + 8)..<(off + 8 + max(0, len - 1)))
                value = String(data: raw, encoding: .utf8)
                    ?? String(data: raw, encoding: .isoLatin1) ?? ""
            } else if type == 0x1F {    // VT_LPWSTR
                let len = Int(u32(off + 4))
                guard len > 0, off + 8 + len * 2 <= data.count else { continue }
                let raw = data.subdata(in: (off + 8)..<(off + 8 + max(0, len - 1) * 2))
                value = String(data: raw, encoding: .utf16LittleEndian) ?? ""
            } else {
                continue
            }
            value = value.replacingOccurrences(of: "\0", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            // 老文档的属性串常带乱码，只保留可读部分
            value = String(value.prefix(40))
            guard !value.isEmpty else { continue }
            switch id {
            case 2: info.title = value
            case 4: info.author = value
            case 8: info.lastSavedBy = value
            case 9: info.revision = value
            case 15: info.company = value
            default: break
            }
        }
        return info
    }
}

// MARK: - OFD（GB/T 33190，zip + XML 版式）
//
// 与二进制 Word 不同，OFD 的文字是 XML 里的节点，能读、能改、能复检——
// 所以它走「原位改文字」而不是「转格式」。扫描件型 OFD 的正文在图里，按 OCR 坐标盖。

enum OFD {
    struct Page {
        var index: Int
        var content: String       // zip 内路径
    }

    private static func firstMatch(_ pattern: String, in s: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else { return nil }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return m.numberOfRanges > 1 ? ns.substring(with: m.range(at: 1)) : ns.substring(with: m.range)
    }

    static func isOFD(_ zip: String) -> Bool {
        Confidential.zipList(zip).contains { $0.hasSuffix("OFD.xml") }
    }

    /// OFD.xml → DocRoot，例如 Doc_0/Document.xml
    static func docRoot(_ zip: String) -> String? {
        guard let xml = Confidential.zipMember(zip, "OFD.xml") else { return nil }
        return firstMatch(#"<(?:\w+:)?DocRoot>([^<]+)</(?:\w+:)?DocRoot>"#, in: xml)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Document.xml → 每页的 Content.xml 路径（BaseLoc 相对 DocRoot 所在目录）
    static func pages(_ zip: String) -> [Page] {
        guard let root = docRoot(zip),
              let doc = Confidential.zipMember(zip, root) else { return [] }
        let dir = (root as NSString).deletingLastPathComponent
        var out: [Page] = []
        guard let re = try? NSRegularExpression(pattern: #"BaseLoc="([^"]+)""#) else { return [] }
        let ns = doc as NSString
        for (i, m) in re.matches(in: doc, range: NSRange(location: 0, length: ns.length)).enumerated() {
            let loc = ns.substring(with: m.range(at: 1))
            let path = dir.isEmpty ? loc : dir + "/" + loc
            out.append(Page(index: i + 1, content: path))
        }
        return out
    }

    /// 页面里的可见文字（TextCode 节点）
    static func pageText(_ xml: String) -> String {
        guard let re = try? NSRegularExpression(
            pattern: #"<(?:\w+:)?TextCode[^>]*>(.*?)</(?:\w+:)?TextCode>"#,
            options: [.dotMatchesLineSeparators]) else { return "" }
        let ns = xml as NSString
        return re.matches(in: xml, range: NSRange(location: 0, length: ns.length))
            .map { m -> String in
                var t = ns.substring(with: m.range(at: 1))
                if let r = t.range(of: "<![CDATA["), let end = t.range(of: "]]>") {
                    t = String(t[r.upperBound..<end.lowerBound])
                }
                return t.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
    }

    static func imageRefs(_ xml: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: #"<(?:\w+:)?ImageObject[^>]*?(?:ResourceID|ID)="([^"]+)""#) else { return [] }
        let ns = xml as NSString
        return re.matches(in: xml, range: NSRange(location: 0, length: ns.length)).map { ns.substring(with: $0.range(at: 1)) }
    }

    /// Res 里的图片实体路径（Document.xml 的 Res 索引 → 实际文件；这里按扩展名直接找同名图片）
    static func imageEntries(_ zip: String) -> [String] {
        Confidential.zipList(zip).filter { p in
            let l = p.lowercased()
            return l.contains("/res/") && (l.hasSuffix(".png") || l.hasSuffix(".jpg") || l.hasSuffix(".jpeg"))
        }
    }

    static func hasSignature(_ zip: String) -> Bool {
        Confidential.zipList(zip).contains { $0.lowercased().hasSuffix("signatures.xml") }
    }

    // MARK: 脱密

    /// 把命中的 TextCode 内容换成占位符；返回改后 XML 与改动次数
    static func redactXML(_ xml: String) -> (String, Int) {
        guard let re = try? NSRegularExpression(
            pattern: #"(<(?:\w+:)?TextCode[^>]*>)(.*?)(</(?:\w+:)?TextCode>)"#,
            options: [.dotMatchesLineSeparators]) else { return (xml, 0) }
        let ns = xml as NSString
        var result = xml
        var n = 0
        for m in re.matches(in: xml, range: NSRange(location: 0, length: ns.length)).reversed() {
            var inner = ns.substring(with: m.range(at: 2))
            if let r = inner.range(of: "<![CDATA["), let end = inner.range(of: "]]>") {
                inner = String(inner[r.upperBound..<end.lowerBound])
            }
            guard needsRedaction(inner) else { continue }
            let replacement = ns.substring(with: m.range(at: 1)) + "【已脱密】" + ns.substring(with: m.range(at: 3))
            result = (result as NSString).replacingCharacters(in: m.range, with: replacement)
            n += 1
        }
        return (result, n)
    }

    static func needsRedaction(_ text: String) -> Bool {
        if let (level, _) = Confidential.classification(in: text), level.isReportable { return true }
        for token in Confidential.matches(#"[0-9]{11,18}"#, in: text) {
            if Confidential.isIdCard(token) || Confidential.isBankCard(token) { return true }
            if token.count == 11 && token.hasPrefix("1") { return true }   // 手机号
        }
        return false
    }

    /// 重打包：改写指定成员，其余原样复制
    static func repack(src: String, to dst: String, edits: [String: Data]) -> Bool {
        let parts = Confidential.zipList(src)
        guard !parts.isEmpty else { return false }
        let fm = FileManager.default
        let work = URL(fileURLWithPath: NSTemporaryDirectory() + "jingpan-ofd-" + UUID().uuidString)
        try? fm.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: work) }

        for part in parts {
            let target = work.appendingPathComponent(part)
            try? fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = edits[part] ?? Confidential.zipMemberData(src, part) ?? Data()
            try? data.write(to: target)
        }
        try? fm.removeItem(atPath: dst)
        let z = Process()
        z.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        z.arguments = ["-q", "-r", "-X", dst] + parts
        z.currentDirectoryURL = work
        do { try z.run() } catch { return false }
        z.waitUntilExit()
        return fm.fileExists(atPath: dst)
    }
}

// MARK: - 扫描器

enum Confidential {
    struct Result {
        var findings: [ConfFinding] = []
        var files = 0
        var skipped = 0
        var bytes: Int64 = 0
        var ocrPages = 0
        var seconds: Double = 0
        var scannedTextFiles = 0
    }

    // MARK: 校验位规则

    private static let idWeights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    private static let idCheck = Array("10X98765432")
    private static let usccCharset = Array("0123456789ABCDEFGHJKLMNPQRTUWXY")
    private static let usccWeights = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]

    static func isIdCard(_ s: String) -> Bool {
        let chars = Array(s.uppercased())
        guard chars.count == 18, chars[0...16].allSatisfy({ $0.isNumber }) else { return false }
        let year = Int(String(chars[6...9])) ?? 0
        let month = Int(String(chars[10...11])) ?? 0
        let day = Int(String(chars[12...13])) ?? 0
        guard year >= 1900, year <= 2100, (1...12).contains(month), (1...31).contains(day) else { return false }
        var sum = 0
        for i in 0..<17 { sum += (Int(String(chars[i])) ?? 0) * idWeights[i] }
        return chars[17] == idCheck[sum % 11]
    }

    static func isUSCC(_ s: String) -> Bool {
        let chars = Array(s.uppercased())
        guard chars.count == 18, chars[0...16].allSatisfy({ usccCharset.contains($0) }) else { return false }
        var sum = 0
        for i in 0..<17 {
            guard let v = usccCharset.firstIndex(of: chars[i]) else { return false }
            sum += v * usccWeights[i]
        }
        return chars[17] == usccCharset[(31 - sum % 31) % 31]
    }

    static func isBankCard(_ s: String) -> Bool {
        let digits = Array(s)
        guard (16...19).contains(digits.count), digits.allSatisfy({ $0.isNumber }) else { return false }
        var sum = 0
        for (i, c) in digits.reversed().enumerated() {
            var d = Int(String(c)) ?? 0
            if i % 2 == 1 { d *= 2; if d > 9 { d -= 9 } }
            sum += d
        }
        return sum % 10 == 0
    }

    static func mask(_ s: String) -> String {
        let a = Array(s)
        if a.count <= 6 { return String(repeating: "·", count: a.count) }
        return String(a.prefix(3)) + String(repeating: "·", count: max(3, a.count - 7)) + String(a.suffix(4))
    }

    // MARK: 密级口径（国家秘密，写法容忍空格、★☆、级、括号与期限）

    private static let levelRules: [(SecretLevel, String)] = [
        (.topSecret, #"绝\s*密"#),
        (.confidential, #"机\s*密"#),
        (.secret, #"秘\s*密"#),
    ]

    /// 不该被读成密级的上下文：商业秘密、个人隐私、解密新闻
    private static let levelExceptions = ["商业秘密", "个人秘密", "技术秘密", "私密", "解密", "泄密", "保密法", "保密工作", "保密协议"]

    /// 只认「标志」不认「提到」：密级标志是独占一行、通常跟星号或期限的短语；
    /// 在谈论密级，而不是在标注密级。表格单元格里的「秘密」、说明书里的「字样」都是这一类。
    /// 刻意不把引号算进来：真实的密级标志也常被写成「机密」★ 期限…，按引号降级会漏报。
    private static func isTalkingAbout(_ line: String, matched: String) -> Bool {
        // 表格单元格里的裸词：命中词前后都是竖线，且整行没有星号/期限。
        // 不能只看「有没有 |」——真标志也常被写进表格（秘密 | 期限10年），那样会漏报。
        let marked = ["★", "☆", "*", "期限"].contains { line.contains($0) }
        if !marked, let r = line.range(of: matched) {
            let before = line[line.startIndex..<r.lowerBound]
            let after = line[r.upperBound...]
            let pipeNear = before.hasSuffix("|") || before.hasSuffix("| ")
                || after.hasPrefix("|") || after.hasPrefix(" |")
            if pipeNear { return true }
        }
        let talk = ["字样", "二字", "一词", "所谓", "称为", "并非", "不得写成",
                    "如何标注", "标注为", "写成「"]
        return talk.contains { line.contains($0) }
    }

    /// 正文里说「绝密级公文如何如何」不算。全盘扫描对这一条极敏感。
    static func classification(in text: String) -> (SecretLevel, String)? {
        let head = String(text.prefix(4000))
        var best: (SecretLevel, String)? = nil
        for rawLine in head.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, line.count <= 40 else { continue }
            if levelExceptions.contains(where: { line.contains($0) }) { continue }
            // 工作秘密单独认：它含「秘密」二字，按国密规则会被误读成「秘密★」；
            // 「内部资料 / 内部使用 / 注意保密」这类不再算任何等级
            if line.contains("工作秘密") {
                // 和国密用同一套「标志」判据：位置太靠后、又带逗号句号的是正文叙述
                let pos = (line as NSString).range(of: "工作秘密").location
                let marked = ["★", "☆", "*", "期限"].contains { line.contains($0) }
                let prose = line.contains("，") || line.contains("。") || line.contains("；")
                if (marked || pos <= 3) && !(prose && !marked), !isTalkingAbout(line, matched: "工作秘密") {
                    if best == nil { best = (.workSecret, "工作秘密") }
                }
                continue
            }
            for (level, pattern) in levelRules {
                guard let re = try? NSRegularExpression(pattern: pattern) else { continue }
                let ns = line as NSString
                guard let m = re.firstMatch(in: line, range: NSRange(location: 0, length: ns.length)) else { continue }
                // 卡的正是「标志」：带星号/期限/密级字样，或密级词就在行首 3 个字内；
                // 不含这些标记、又带逗号句号的，是正文里的叙述（「绝密级公文应当如何管理」），不算
                // 注意不能把「密级」放进标记词：它是「绝密级 / 机密级」的子串，
                // 一放进去，正文里的「绝密级公文应当…」就又算成标志了
                let markerish = ["★", "☆", "*", "期限"].contains { line.contains($0) }
                let atLineStart = m.range.location <= 3
                let prose = line.contains("，") || line.contains("。") || line.contains("；")
                guard markerish || atLineStart else { continue }
                if prose && !markerish { continue }
                let matched = ns.substring(with: m.range)
                if isTalkingAbout(line, matched: matched) { continue }
                if best == nil || level > best!.0 { best = (level, matched) }
            }
        }
        return best
    }

    // MARK: 文件类型

    static let textExts: Set<String> = ["txt", "md", "csv", "json", "xml", "html", "htm", "rtf", "log", "srt"]
    static let officeExts: Set<String> = ["docx", "xlsx", "pptx", "docm", "xlsm", "pptm"]
    static let legacyOffice: Set<String> = ["doc", "xls", "ppt", "wps", "et", "dps", "wpt", "ett", "dpt"]
    static let pdfExts: Set<String> = ["pdf"]
    static let imageExts: Set<String> = ["jpg", "jpeg", "png", "heic", "tif", "tiff", "dng"]
    static let ofdExts: Set<String> = ["ofd"]

    static let maxFileBytes: Int64 = 80 * 1024 * 1024
    static let maxTextChars = 200_000
    static let maxOCRPpages = 40

    // MARK: 主流程

    static func scan(root: URL, limit: Int = 3000, ocr: Bool = true,
                     progress: ((Int, Int) -> Void)? = nil) -> Result {
        let started = Date()
        var r = Result()
        // 枚举失败（没权限、盘断了）必须记下来：不然结论会替一个没看全的目录说「未发现」
        var denied: [String] = []
        guard let en = FileManager.default.enumerator(
            at: root, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants],
            errorHandler: { url, _ in
                denied.append(url.path)
                return true
            }) else {
            r.skipped += 1
            r.findings.append(ConfFinding(kind: .unscannable, file: root.lastPathComponent, place: "目录",
                                          value: "打不开", note: "整个目录没能枚举，内容未检查", level: .info))
            return r
        }
        var paths: [URL] = []
        for case let u as URL in en {
            guard paths.count < limit else { break }
            if u.pathComponents.contains("trash") { continue }   // 自己的备份不算待检查内容
            if (try? u.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true { paths.append(u) }
        }
        let base = root.resolvingSymlinksInPath().path
        for p in denied {
            let rel = p.hasPrefix(base + "/") ? String(p.dropFirst(base.count + 1)) : (p as NSString).lastPathComponent
            r.skipped += 1
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "目录",
                                          value: "无权限", note: "这个目录没读成，内容未检查", level: .info))
        }
        for (i, u) in paths.enumerated() {
            progress?(i + 1, paths.count)
            r.files += 1
            let size = Int64((try? u.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
            r.bytes += size
            let real = u.resolvingSymlinksInPath().path
            let rel = real.hasPrefix(base + "/") ? String(real.dropFirst(base.count + 1)) : u.lastPathComponent
            if size > maxFileBytes {
                r.skipped += 1
                r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                              value: Fmt.bytes(size), note: "文件太大，没查内容", level: .info))
                continue
            }
            inspect(u, rel: rel, ocr: ocr, into: &r)
        }
        r.findings.sort { ($0.level, $0.file) > ($1.level, $1.file) }
        r.seconds = Date().timeIntervalSince(started)
        return r
    }

    static func inspectFileForCLI(_ u: URL, ocr: Bool, into r: inout Result) {
        r.files = 1
        r.bytes = Int64((try? u.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        inspect(u, rel: u.lastPathComponent, ocr: ocr, into: &r)
        r.findings.sort { ($0.level, $0.file) > ($1.level, $1.file) }
    }

    private static func inspect(_ u: URL, rel: String, ocr: Bool, into r: inout Result) {
        let ext = u.pathExtension.lowercased()
        if textExts.contains(ext) {
            if let t = readText(u) { scanText(t, file: rel, place: "正文", into: &r) }
        } else if officeExts.contains(ext) {
            inspectOOXML(u, rel: rel, into: &r)
        } else if pdfExts.contains(ext) {
            inspectPDF(u, rel: rel, ocr: ocr, into: &r)
        } else if imageExts.contains(ext) {
            inspectImage(u, rel: rel, ocr: ocr, into: &r)
        } else if legacyOffice.contains(ext) {
            inspectCFB(u, rel: rel, into: &r)
        } else if ofdExts.contains(ext) {
            inspectOFD(u, rel: rel, ocr: ocr, into: &r)
        }
    }

    // MARK: WPS / 旧版 Office（OLE 复合文档）

    static func inspectCFB(_ u: URL, rel: String, into r: inout Result) {
        guard let d = try? Data(contentsOf: u), d.count <= maxFileBytes else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                          value: "cfa", note: "读不出来，内容未检查", level: .info))
            return
        }
        guard CFB.magic(d) else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                          value: u.pathExtension.lowercased(),
                                          note: "不是标准 OLE 文档，内容未检查", level: .info))
            return
        }
        let names = CFB.entryNames(d)

        // 加密：能给结论就不要假装查过
        if names.contains(where: { $0 == "EncryptionInfo" || $0 == "EncryptedPackage" || $0 == "DataSpaces" }) {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "加密",
                                          value: "已加密", note: "文档加密，内容未检查", level: .info))
            return
        }

        // 正文：二进制里找可见文字。能找到就报，找不到不代表没有。
        let textStreams = ["WordDocument", "Workbook", "Book", "PowerPoint Document"]
        var raw = Data()
        for name in textStreams {
            if let s = CFB.stream(d, name: name) { raw.append(s) }
        }
        if raw.isEmpty { raw = d }

        // 旧版 Office / WPS 的正文夹在二进制里，直接解码得到的是碎片、行界也乱了，
        // 密级标志（要求独占一行）会漏判。有 textutil 就先让它给一份干净正文。
        if let t = textutilText(u), textCJKCount(Data(t.utf8)) >= 8 {
            scanText(t, file: rel, place: "正文", into: &r)
            r.scannedTextFiles += 1
            return
        }

        // 没有 textutil 可用时退回容错解码（一有坏字节就 nil 的 String(data:encoding:) 不能用）
        scanText(decodeUTF16(raw), file: rel, place: "二进制正文（位置未定位）", into: &r)
        if let t = String(data: raw, encoding: .utf8) {
            scanText(t, file: rel, place: "二进制正文（位置未定位）", into: &r)
        }
        if textCJKCount(raw) < 8 {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "二进制",
                                          value: "未取到正文", note: "没能从二进制里取到足够文字（可能是图片或特殊编码），需人工确认",
                                          level: .info))
        } else {
            // 取到正文；命中已在上面报过，没有命中就由摘要体现
            r.scannedTextFiles += 1
        }
    }

    /// 让系统 textutil 把旧格式正文转成纯文本（不依赖 LibreOffice）
    static func textutilText(_ u: URL) -> String? {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: u.path, isDirectory: &isDir), !isDir.boolValue,
              let size = (try? u.resourceValues(forKeys: [.fileSizeKey]).fileSize), size < 60_000_000 else { return nil }
        let r = Shell.run("/usr/bin/textutil", ["-convert", "txt", "-stdout", u.path], timeout: 30)
        guard r.ok else { return nil }
        let t = r.out
        return t.isEmpty ? nil : t
    }

    /// 容错解码：二进制里总会有坏字节，不能因为一个坏代理项就把整段文字丢掉
    static func decodeUTF16(_ d: Data) -> String {
        let data = d.count % 2 == 1 ? d.dropLast() : d
        let units = data.withUnsafeBytes { Array($0.bindMemory(to: UInt16.self)) }
        return String(decoding: units, as: UTF16.self)
    }

    static func textCJKCount(_ raw: Data) -> Int {
        func cjk(_ t: String) -> Int {
            t.unicodeScalars.filter { (0x4E00...0x9FFF).contains($0.value) }.count
        }
        var best = cjk(decodeUTF16(raw))
        if let t = String(data: raw, encoding: .utf8) { best = max(best, cjk(t)) }
        let gb = CFStringConvertEncodingToNSStringEncoding(CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue))
        if let t = String(data: raw, encoding: String.Encoding(rawValue: gb)) {
            best = max(best, t.unicodeScalars.filter { (0x4E00...0x9FFF).contains($0.value) }.count)
        }
        return best
    }

    // MARK: 文本规则

    /// 取命中前后各 14 个字，并把命中处用「」标出来；换行压成空格
    static func snippet(_ text: String, at range: NSRange, token: String, span: Int = 14) -> String {
        let ns = text as NSString
        let start = max(0, range.location - span)
        let end = min(ns.length, range.location + range.length + span)
        var s = ns.substring(with: NSRange(location: start, length: end - start))
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
        while s.contains("  ") { s = s.replacingOccurrences(of: "  ", with: " ") }
        if let r = s.range(of: token) { s.replaceSubrange(r, with: "「\(token)」") }
        return (start > 0 ? "…" : "") + s.trimmingCharacters(in: .whitespaces) + (end < ns.length ? "…" : "")
    }

    static func scanText(_ raw: String, file: String, place: String, into r: inout Result, viaOCR: Bool = false) {
        let text = String(raw.prefix(maxTextChars))

        if let (level, matched) = classification(in: text) {
            var ctx = ""
            if let range = text.range(of: matched) {
                ctx = snippet(text, at: NSRange(range, in: text), token: matched, span: 18)
            }
            r.findings.append(ConfFinding(kind: .classification, file: file, place: place,
                                          value: matched,
                                          note: level.isStateSecret ? "文首出现国家秘密标志（\(level.label)）"
                                                                    : "文首出现工作秘密标志",
                                          level: level, viaOCR: viaOCR, context: ctx))
        }
        // 证件号、手机号、统一社会信用代码一律不再报：口径只认国家秘密与工作秘密
    }

    static func matches(_ pattern: String, in text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length))
            .map { ns.substring(with: $0.range) }
    }

    static func readText(_ u: URL) -> String? {
        guard let d = try? Data(contentsOf: u), d.count <= maxFileBytes else { return nil }
        let gb = CFStringConvertEncodingToNSStringEncoding(CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue))
        return String(data: d, encoding: .utf8) ?? String(data: d, encoding: String.Encoding(rawValue: gb))
    }

    // MARK: OOXML

    static func zipMember(_ path: String, _ member: String) -> String? {
        let (out, ok) = Shell.run("/usr/bin/unzip", ["-p", path, member])
        return ok && !out.isEmpty ? out : nil
    }

    static func zipMemberData(_ path: String, _ member: String) -> Data? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        p.arguments = ["-p", path, member]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { return nil }
        let d = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return p.terminationStatus == 0 && !d.isEmpty ? d : nil
    }

    static func zipList(_ path: String) -> [String] {
        let (out, ok) = Shell.run("/usr/bin/unzip", ["-Z1", path])
        guard ok else { return [] }
        return out.split(separator: "\n").map(String.init)
    }

    static func stripXML(_ xml: String) -> String {
        var s = xml.replacingOccurrences(of: "<[^>]+>", with: " ", options: .regularExpression)
        s = s.replacingOccurrences(of: "&amp;", with: "&")
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&apos;", with: "'")
        return s.replacingOccurrences(of: "[ \\t]+", with: " ", options: .regularExpression)
    }

    static func inspectOOXML(_ u: URL, rel: String, into r: inout Result) {
        let path = u.path
        // 一次调用把正文成员全取出来：原先每个成员一次 unzip，一个 docx 就要起十几个进程，
        // 扫描几万个文件时进程启动本身比读内容还贵
        let patterns: [String]
        switch u.pathExtension.lowercased() {
        case "xlsx", "xlsm":
            patterns = ["xl/sharedStrings.xml", "xl/worksheets/*.xml"]
        case "pptx", "pptm":
            patterns = ["ppt/slides/*.xml", "ppt/notesSlides/*.xml"]
        default:
            patterns = ["word/document.xml", "word/header*.xml", "word/footer*.xml",
                        "word/footnotes.xml", "word/endnotes.xml"]
        }
        // unzip 只要有一个通配符没匹配上就返回 11，所以看输出、不看退出码
        let res = Shell.run("/usr/bin/unzip", ["-p", path] + patterns, timeout: 60)
        var raw = res.out
        guard !raw.isEmpty else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                          value: "zip", note: "打不开（可能加密），内容未检查", level: .info))
            return
        }
        // 几百万字的表格没必要整篇扫：取前 4 MB，密级标志在卷首
        if raw.count > 4_000_000 { raw = String(raw.prefix(4_000_000)) }
        // 段落结束转成换行：密级标志要求「独占一行」，全压成一行就永远判不出来
        var text = raw
        for (tag, sep) in [("</w:p>", "\n"), ("</a:p>", "\n"), ("</si>", "\n"), ("<w:br/>", "\n")] {
            text = text.replacingOccurrences(of: tag, with: sep)
        }
        // 各成员拼在一起扫即可：只要文字，不必区分来自哪个成员
        scanText(stripXML(text), file: rel, place: "正文", into: &r)
        r.scannedTextFiles += 1
    }

    static func firstTag(_ xml: String, _ tag: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: "<\(tag)[^>]*>([^<]*)</\(tag)>") else { return nil }
        let ns = xml as NSString
        guard let m = re.firstMatch(in: xml, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return stripXML(ns.substring(with: m.range(at: 1))).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: OFD（zip + XML：文字在节点里，扫得到也改得动）

    static func inspectOFD(_ u: URL, rel: String, ocr: Bool, into r: inout Result) {
        let parts = zipList(u.path)
        guard !parts.isEmpty else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                          value: "zip", note: "打不开的 OFD，内容未检查", level: .info))
            return
        }
        guard OFD.isOFD(u.path) else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                          value: "ofd", note: "没有 OFD.xml，不是标准 OFD，内容未检查", level: .info))
            return
        }
        let pages = OFD.pages(u.path)
        guard !pages.isEmpty else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                          value: "无页面", note: "读不到页面结构，内容未检查", level: .info))
            return
        }
        var textFound = 0
        for p in pages {
            guard let xml = zipMember(u.path, p.content) else { continue }
            let t = OFD.pageText(xml)
            if !t.isEmpty {
                textFound += 1
                scanText(t, file: rel, place: "第 \(p.index) 页", into: &r)
            }
        }
        // 扫描件型：页面里只有图片时，图片才是正文
        let images = OFD.imageEntries(u.path)
        if textFound == 0 && !images.isEmpty {
            if ocr {
                for (i, path) in images.prefix(20).enumerated() {
                    guard let data = zipMemberData(u.path, path),
                          let src = CGImageSourceCreateWithData(data as CFData, nil),
                          let cg = CGImageSourceCreateImageAtIndex(src, 0, nil) else { continue }
                    let t = OCR.text(from: cg)
                    r.ocrPages += 1
                    if !t.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        scanText(t, file: rel, place: "第 \(i + 1) 张图·OCR", into: &r, viaOCR: true)
                    }
                }
            } else {
                r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "图片页",
                                              value: "无文字层", note: "扫描型 OFD，未做 OCR，内容未检查", level: .info))
            }
        }
    }

    // MARK: PDF（有文字层就读文字层，没有就 OCR）

    static func inspectPDF(_ u: URL, rel: String, ocr: Bool, into r: inout Result) {
        guard let doc = PDFDocument(url: u) else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                          value: "pdf", note: "打不开（可能加密或损坏），内容未检查", level: .info))
            return
        }
        var text = ""
        for i in 0..<min(doc.pageCount, 30) {
            if let p = doc.page(at: i)?.string { text += p + "\n" }
            if text.count > maxTextChars { break }
        }

        let hasTextLayer = text.trimmingCharacters(in: .whitespacesAndNewlines).count > 20
        if hasTextLayer {
            scanText(text, file: rel, place: "\(doc.pageCount) 页正文", into: &r)
        } else if ocr {
            let n = min(doc.pageCount, maxOCRPpages)
            var pages = [String](repeating: "", count: n)
            DispatchQueue.concurrentPerform(iterations: n) { i in
                if let p = doc.page(at: i) { pages[i] = OCR.text(from: p) }
            }
            let ocrText = pages.joined(separator: "\n")
            r.ocrPages += n
            if ocrText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "\(doc.pageCount) 页",
                                              value: "OCR 无结果", note: "扫描件识别不出文字，内容未检查", level: .info))
            } else {
                scanText(ocrText, file: rel, place: "\(doc.pageCount) 页·OCR", into: &r, viaOCR: true)
            }
        } else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "\(doc.pageCount) 页",
                                          value: "无文字层", note: "扫描件，未做 OCR，内容未检查", level: .info))
        }

    }

    // MARK: 图片（元数据 + OCR）

    static func inspectImage(_ u: URL, rel: String, ocr: Bool, into r: inout Result) {
        guard let src = CGImageSourceCreateWithURL(u as CFURL, nil),
              CGImageSourceCreateImageAtIndex(src, 0, nil) != nil else {
            r.findings.append(ConfFinding(kind: .unscannable, file: rel, place: "—",
                                          value: "image", note: "读不出图片，未检查", level: .info))
            return
        }
        // 元数据里的拍摄地点、机型不再报
        if ocr {
            let t = OCR.text(fromImageAt: u)
            r.ocrPages += 1
            if !t.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                scanText(t, file: rel, place: "图片·OCR", into: &r, viaOCR: true)
            }
        }
    }
}

// MARK: - 报告

extension Confidential.Result {
    func text(limit: Int = 60) -> String {
        var lines: [String] = []
        lines.append("保密体检：\(files) 个文件，\(Fmt.bytes(bytes))，\(String(format: "%.1f", seconds)) 秒"
                     + (ocrPages > 0 ? "，OCR \(ocrPages) 页" : ""))
        let state = findings.filter { $0.level.isStateSecret }
        if state.isEmpty {
            // 「没看到」不是「没有」：没查全的时候，通过结论必须带着缺口一起出现
            let blind = findings.filter { $0.kind == .unscannable }.count
            if blind > 0 {
                lines.append("国家秘密标志：未发现（但 \(blind) 处没查成，结论不完整）")
            } else {
                lines.append("国家秘密标志：未发现")
            }
        } else {
            let worst = state.map { $0.level }.max()!
            lines.append("国家秘密标志：**发现 \(worst.label)**（\(state.count) 处）")
        }
        let work = findings.filter { $0.level == .workSecret }.count
        let info = findings.filter { $0.level == .info }.count
        lines.append("工作秘密：\(work) 处；未检查（判不了内容）：\(info) 处")
        if skipped > 0 {
            lines.insert("没查：\(skipped) 处（没权限或读不出，这部分等于没看）", at: 1)
        }
        lines.append("")
        if findings.isEmpty {
            lines.append("没有发现国家秘密或工作秘密标志。")
            lines.append("注意：这只代表本次规则没命中，不等于这份材料可以对外提供。")
            return lines.joined(separator: "\n")
        }

        var groups: [(file: String, worst: SecretLevel, items: [ConfFinding])] = []
        for f in findings {
            if let i = groups.firstIndex(where: { $0.file == f.file }) {
                groups[i].items.append(f)
                groups[i].worst = max(groups[i].worst, f.level)
            } else {
                groups.append((f.file, f.level, [f]))
            }
        }
        groups.sort { ($0.worst, $0.items.count) > ($1.worst, $1.items.count) }

        var printed = 0
        for g in groups {
            guard printed < limit else { break }
            lines.append("▸ \(g.file)")
            for f in g.items.sorted(by: { $0.level > $1.level }) {
                guard printed < limit else { break }
                let tag = f.level.isReportable ? "【\(f.level.label)】" : "【提示】"
                let ocr = f.viaOCR ? "（OCR）" : ""
                lines.append("   \(tag)\(f.kind.rawValue)  \(f.place)\(ocr)  \(f.value)  — \(f.note)")
                printed += 1
            }
        }
        if findings.count > printed { lines.append("… 还有 \(findings.count - printed) 条") }
        lines.append("")
        lines.append("本次只做检查，没有改动任何文件。")
        return lines.joined(separator: "\n")
    }

    var json: String {
        let arr: [[String: Any]] = findings.map {
            ["kind": $0.kind.rawValue, "file": $0.file, "place": $0.place,
             "value": $0.value, "note": $0.note, "level": $0.level.rawValue,
             "label": $0.level.label, "viaOCR": $0.viaOCR]
        }
        let obj: [String: Any] = ["files": files, "bytes": bytes, "skipped": skipped,
                                  "ocrPages": ocrPages, "seconds": seconds, "findings": arr]
        let d = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys])
        return d.flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }

    /// 一个文件是否还有「需要处理」的命中
    static func hits(of file: String, in findings: [ConfFinding]) -> [ConfFinding] {
        findings.filter { $0.file == file }
    }
}

// MARK: - 脱密（产出干净副本，原件进 trash）

enum Declass {
    /// 跨卷 moveItem 会抛 EXDEV：先试 move，失败就 copy + remove
    static func transfer(_ from: URL, _ to: URL) throws {
        do {
            try FileManager.default.moveItem(at: from, to: to)
        } catch {
            try FileManager.default.copyItem(at: from, to: to)
            try FileManager.default.removeItem(at: from)
        }
    }

    struct Outcome {
        var file: String
        var newFile: String?
        var actions: [String] = []
        var verified = false
        var trashedTo: String?
        var error: String?
        var ok: Bool { error == nil && verified }
    }

    /// 支持的格式与它的处理方式；不支持的必须明说，不许"尽力而为"
    static func capability(_ ext: String) -> (ok: Bool, what: String) {
        switch ext {
        case "txt", "md", "csv", "json", "xml", "html", "htm", "log":
            return (true, "遮盖命中内容 + 删除密级标志行")
        case "docx", "xlsx", "pptx", "docm", "xlsm", "pptm":
            return (true, "清属性 + 删批注 + 接受修订 + 遮盖命中内容")
        case "jpg", "jpeg", "png", "heic", "tif", "tiff":
            return (true, "重编码，去掉全部元数据（含 GPS）")
        case "pdf":
            return (true, "清 PDF 属性；文字层命中会遮盖为方块并保留版式")
        case "wps", "doc":
            return (true, "用 LibreOffice 转成 docx 后脱密（原格式不保留，版式可能变）")
        case "et", "xls":
            return (true, "用 LibreOffice 转成 xlsx 后脱密（原格式不保留）")
        case "dps", "ppt", "dpt":
            return (true, "用 LibreOffice 转成 pptx 后脱密（原格式不保留）")
        case "wpt":
            return (true, "用 LibreOffice 转成 docx 后脱密（原格式不保留）")
        case "ett":
            return (true, "用 LibreOffice 转成 xlsx 后脱密（原格式不保留）")
        case "ofd":
            return (true, "改写文字层 + 遮盖图片；已签章的 OFD 不自动处理")
        default:
            return (false, "该格式暂不支持自动脱密")
        }
    }

    // MARK: 文本

    static let maskToken = "【已脱密】"

    static func cleanText(_ s: String) -> String {
        var out = s
        // 整行的密级标志直接删掉，不留下「【已脱密】★」这种残迹
        let lines = out.components(separatedBy: "\n")
        out = lines.filter { line in
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.isEmpty else { return true }
            if let (level, _) = Confidential.classification(in: t), level.isReportable {
                // 只删「标志行」：以标志开头且长度不长
                let head = String(t.prefix(12))
                if let (l2, _) = Confidential.classification(in: head), l2.isReportable, t.count <= 40 { return false }
            }
            return true
        }.joined(separator: "\n")

        for pattern in [#"(?<![0-9])[0-9]{17}[0-9Xx](?![0-9])"#, #"(?<![0-9])[1-9][0-9]{15,18}(?![0-9])"#,
                        #"(?<![0-9])1[3-9][0-9]{9}(?![0-9])"#, #"(?<![0-9A-Z])[0-9A-HJ-NPQRTUWXY]{18}(?![0-9A-Z])"#] {
            if let re = try? NSRegularExpression(pattern: pattern) {
                let ns = out as NSString
                let ms = re.matches(in: out, range: NSRange(location: 0, length: ns.length))
                for m in ms.reversed() {
                    let hit = ns.substring(with: m.range)
                    let keep = Confidential.isIdCard(hit) || Confidential.isBankCard(hit)
                        || Confidential.isUSCC(hit) || (hit.count == 11 && hit.hasPrefix("1"))
                    if keep { out = (out as NSString).replacingCharacters(in: m.range, with: maskToken) }
                }
            }
        }
        return out
    }

    // MARK: OOXML

    /// 只改需要改的成员，其余原样复制；写完再复检
    static func cleanOOXML(_ src: URL, to dst: URL) -> (actions: [String], error: String?) {
        let parts = Confidential.zipList(src.path)
        guard !parts.isEmpty else { return ([], "打不开 zip") }
        let fm = FileManager.default
        let work = URL(fileURLWithPath: NSTemporaryDirectory() + "baomi-declass-" + UUID().uuidString)
        try? fm.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: work) }

        // 整包解出来再处理：unzip 会把 [Content_Types].xml 里的方括号当成通配符
        let r = Shell.run("/usr/bin/ditto", ["-x", "-k", src.path, work.path], timeout: 60)
        guard r.ok else { return ([], "解包失败") }

        var actions: [String] = []
        var removedParts = Set<String>()

        for part in parts {
            let file = work.appendingPathComponent(part)
            guard let data = fm.contents(atPath: file.path) else {
                return ([], "解包后缺少成员 \(part)")
            }
            var out = data

            if part == "docProps/core.xml" || part == "docProps/app.xml" {
                var xml = String(decoding: data, as: UTF8.self)
                for tag in ["dc:creator", "cp:lastModifiedBy", "Company", "Manager",
                            "dc:title", "dc:subject", "cp:keywords"] {
                    xml = xml.replacingOccurrences(
                        of: "<\(tag)[^>]*>[^<]*</\(tag)>",
                        with: "<\(tag)></\(tag)>", options: .regularExpression)
                }
                out = Data(xml.utf8)
                if !actions.contains("清文档属性") { actions.append("清文档属性") }
            }

            if part.hasSuffix("comments.xml") {
                try? fm.removeItem(at: file)
                removedParts.insert(part)
                if !actions.contains("删批注") { actions.append("删批注") }
                continue
            }

            if part.hasSuffix(".xml") && (part.hasPrefix("word/") || part.hasPrefix("xl/") || part.hasPrefix("ppt/")) {
                var xml = String(decoding: data, as: UTF8.self)
                let before = xml
                if xml.contains("<w:ins") {
                    xml = xml.replacingOccurrences(of: "<w:ins[^>]*>", with: "", options: .regularExpression)
                    xml = xml.replacingOccurrences(of: "</w:ins>", with: "")
                }
                if xml.contains("<w:del") {
                    xml = xml.replacingOccurrences(of: "<w:del [^>]*>.*?</w:del>", with: "", options: .regularExpression)
                    xml = xml.replacingOccurrences(of: "<w:del>.*?</w:del>", with: "", options: .regularExpression)
                    if !actions.contains("接受修订") { actions.append("接受修订") }
                }
                xml = xml.replacingOccurrences(of: "<w:commentReference[^>]*/>", with: "", options: .regularExpression)
                // 密级标志独占一段时整段删掉；段里还有正文就退回遮盖（见 stripMarkerParagraphs）
                if part.hasPrefix("word/") {
                    let (x, n) = stripMarkerParagraphs(xml, openTag: "w:p", textTag: "w:t")
                    if n > 0 {
                        xml = x
                        if !actions.contains("整段删除密级标志") { actions.append("整段删除密级标志") }
                    }
                } else if part.hasPrefix("ppt/") {
                    let (x, n) = stripMarkerParagraphs(xml, openTag: "a:p", textTag: "a:t")
                    if n > 0 {
                        xml = x
                        if !actions.contains("整段删除密级标志") { actions.append("整段删除密级标志") }
                    }
                }
                for (open, close) in [("<w:t", "</w:t>"), ("<a:t>", "</a:t>"), ("<t>", "</t>")] {
                    xml = maskInXMLText(xml, open: open, close: close)
                }
                if xml != before {
                    out = Data(xml.utf8)
                    if !actions.contains("遮盖命中内容") { actions.append("遮盖命中内容") }
                }
            }

            if out != data { try? out.write(to: file) }
        }

        try? fm.removeItem(at: dst)
        let z = Process()
        z.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        z.arguments = ["-q", "-r", "-D", "-X", dst.path, "."]
        z.currentDirectoryURL = work
        z.standardError = FileHandle.nullDevice
        do { try z.run() } catch { return (actions, "打包失败") }
        z.waitUntilExit()
        guard z.terminationStatus == 0 else { return (actions, "打包退出码 \(z.terminationStatus)") }

        let after = Set(Confidential.zipList(dst.path).filter { !$0.hasSuffix("/") })
        guard after == Set(parts).subtracting(removedParts), !after.isEmpty else {
            return (actions, "重打包后成员不一致（\(after.count)/\(parts.count)）")
        }
        return (actions, nil)
    }

    /// 段落里的纯文字（把该段所有文本节点拼起来）
    static func paragraphText(_ snippet: String, textTag: String) -> String {
        guard let re = try? NSRegularExpression(
            pattern: "<\(textTag)[^>]*>([^<]*)</\(textTag)>") else { return "" }
        let ns = snippet as NSString
        let parts = re.matches(in: snippet, range: NSRange(location: 0, length: ns.length))
            .map { ns.substring(with: $0.range(at: 1)) }
        return parts.joined()
    }

    /// 只留下「标志」的段落：长度很短，且去掉标志、星号、期限短语之后基本没有别的内容
    static func isMarkerParagraph(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.count <= 40 else { return false }
        guard let (level, _) = Confidential.classification(in: t), level.isReportable else { return false }
        var rest = t
        for pattern in [#"[★☆*]"#, #"(绝\s*密|机\s*密|秘\s*密|工作秘密)"#,
                        #"保\s*密\s*期\s*限\s*[0-9〇一二三四五六七八九十]+\s*年?"#,
                        #"[\s:：·—\-（）()\[\]【】]"#] {
            rest = rest.replacingOccurrences(of: pattern, with: "", options: .regularExpression)
        }
        return rest.count <= 2
    }

    /// 删掉只装密级标志的整段。要动段落结构，所以只在「这段除了标志没别的」时动手；
    /// 段落里还有正文时保持原样，交给 maskInXMLText 遮盖
    static func stripMarkerParagraphs(_ xml: String, openTag: String, textTag: String) -> (String, Int) {
        let ns = xml as NSString
        let n = ns.length
        let closeTag = "</\(openTag)>"
        var paragraphs: [NSRange] = []
        var stack: [Int] = []
        var i = 0
        while i < n {
            let rest = NSRange(location: i, length: n - i)
            let nx = ns.range(of: "<\(openTag)", options: [], range: rest)
            let nc = ns.range(of: closeTag, options: [], range: rest)
            if nc.location == NSNotFound { break }

            // "<w:p" 也会命中 "<w:pPr"：只有紧跟 > / 空格 / 斜杠的才算段落开头
            var opening: Int? = nil
            if nx.location != NSNotFound && nx.location < nc.location {
                let afterName = nx.location + nx.length
                if afterName < n {
                    let c = ns.substring(with: NSRange(location: afterName, length: 1))
                    if [">", " ", "/", "\n", "\t", "\r"].contains(c) { opening = nx.location }
                }
            }
            guard let start = opening else {
                if nx.location != NSNotFound && nx.location < nc.location {
                    i = nx.location + nx.length     // 不是段落开头，跳过去继续
                } else {
                    let end = nc.location + nc.length
                    if let start = stack.popLast() {
                        paragraphs.append(NSRange(location: start, length: end - start))
                    }
                    i = end
                }
                continue
            }

            let tagEnd = ns.range(of: ">", options: [],
                                  range: NSRange(location: start, length: n - start)).location
            guard tagEnd != NSNotFound else { break }
            let selfClosing = tagEnd > start
                && ns.substring(with: NSRange(location: tagEnd - 1, length: 1)) == "/"
            if !selfClosing { stack.append(start) }      // <w:p/> 不占栈
            i = tagEnd + 1
        }
        guard !paragraphs.isEmpty else { return (xml, 0) }

        let ns2 = xml as NSString
        var result = xml
        var removed = 0
        var removedRanges: [NSRange] = []
        // 从后往前删，前面的下标才不会串；被外层段落包住的不再单独处理
        for range in paragraphs.sorted(by: { $0.location > $1.location }) {
            if removedRanges.contains(where: { NSIntersectionRange($0, range).length > 0 }) { continue }
            guard isMarkerParagraph(paragraphText(ns2.substring(with: range), textTag: textTag)) else { continue }
            result = (result as NSString).replacingCharacters(in: range, with: "")
            removedRanges.append(range)
            removed += 1
        }
        return (result, removed)
    }

    static func maskInXMLText(_ xml: String, open: String, close: String) -> String {
        guard let re = try? NSRegularExpression(
            pattern: "\(open)[^>]*>[^<]*\(close)", options: []) else { return xml }
        let ns = xml as NSString
        var result = xml
        let ms = re.matches(in: xml, range: NSRange(location: 0, length: ns.length))
        for m in ms.reversed() {
            let snippet = ns.substring(with: m.range)
            let inner = Confidential.classification(in: snippet).map { $0.0.isReportable } ?? false
            let hasPII = Confidential.matches(#"[0-9]{11,19}"#, in: snippet).contains {
                Confidential.isIdCard($0) || Confidential.isBankCard($0)
                    || ($0.count == 11 && $0.hasPrefix("1") && !"012".contains($0.dropFirst().first ?? "0"))
            }
            guard inner || hasPII || snippet.contains("绝密") || snippet.contains("机密") || snippet.contains("秘密") else { continue }
            var replaced = snippet
            for p in [#"[0-9]{17}[0-9Xx]"#, #"[0-9]{16,19}"#, #"[0-9]{11}"#] {
                replaced = replaced.replacingOccurrences(of: p, with: maskToken, options: .regularExpression)
            }
            replaced = replaced.replacingOccurrences(of: "工作秘密", with: maskToken)
                .replacingOccurrences(of: "绝密", with: maskToken)
                .replacingOccurrences(of: "机密", with: maskToken)
                .replacingOccurrences(of: "秘密", with: maskToken)
            result = (result as NSString).replacingCharacters(in: m.range, with: replaced)
        }
        return result
    }

    // MARK: 图片

    static func cleanImage(_ src: URL, to dst: URL) -> [String] {
        guard let s = CGImageSourceCreateWithURL(src as CFURL, nil),
              let img = CGImageSourceCreateImageAtIndex(s, 0, nil) else { return ["读不出图片"] }
        let hits = OCR.hits(in: img)
        let masked = hits.isEmpty ? img : (cover(img, hits: hits) ?? img)
        var actions = ["重编码去元数据"]
        if !hits.isEmpty { actions.append("遮盖 \(hits.count) 处文字") }
        let type = (src.pathExtension.lowercased() == "png") ? "public.png" : "public.jpeg"
        guard let dest = CGImageDestinationCreateWithURL(dst as CFURL, type as CFString, 1, nil) else {
            return ["写不出图片"]
        }
        CGImageDestinationAddImage(dest, masked, nil)   // 不传任何属性 = 不写元数据
        guard CGImageDestinationFinalize(dest) else { return ["写不出图片"] }
        return actions
    }

    /// 按 OCR 给的位置盖白块。Vision 坐标原点在左下，所以 Y 要翻一次。
    static func cover(_ img: CGImage, hits: [OCR.Hit]) -> CGImage? {
        let w = img.width, h = img.height
        guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue) else { return nil }
        // 翻成左上原点，Vision 的归一化矩形才能直接落到像素上
        ctx.translateBy(x: 0, y: CGFloat(h))
        ctx.scaleBy(x: 1, y: -1)
        ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
        ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        for hit in hits {
            let padX = max(4, CGFloat(w) * 0.006)
            let padY = max(4, CGFloat(h) * 0.004)
            ctx.fill(CGRect(x: hit.rect.minX * CGFloat(w) - padX,
                            y: (1 - hit.rect.maxY) * CGFloat(h) - padY,
                            width: hit.rect.width * CGFloat(w) + padX * 2,
                            height: hit.rect.height * CGFloat(h) + padY * 2))
        }
        return ctx.makeImage()
    }

    // MARK: PDF

    static func cleanPDF(_ src: URL, to dst: URL) -> [String] {
        guard let doc = PDFDocument(url: src) else { return ["打不开 PDF"] }
        var actions: [String] = []
        let pages = doc.pageCount

        // 逐页判断：文字层有密级标志，或 OCR 在页面上找到标记/号码，就整页重建
        var maskedPages: [CGImage?] = []
        var covered = 0
        var rebuilt = false
        for i in 0..<pages {
            guard let page = doc.page(at: i) else { maskedPages.append(nil); continue }
            let textHit = page.string.flatMap { Confidential.classification(in: $0) }?.0.isStateSecret ?? false
            let (cg, n) = redactPage(page, dpi: 200)
            if textHit || n > 0, let cg {
                maskedPages.append(cg)
                covered += max(n, 1)
                rebuilt = true
            } else {
                maskedPages.append(nil)   // 干净页保留原页，文字层不丢
            }
        }

        if rebuilt {
            let out = PDFDocument()
            for i in 0..<pages {
                if let cg = maskedPages[i], let p = PDFPage(image: NSImage(cgImage: cg, size: .zero)) {
                    out.insert(p, at: out.pageCount)
                } else if let p = doc.page(at: i) {
                    out.insert(p, at: out.pageCount)
                }
            }
            out.documentAttributes = [:]
            guard out.write(to: dst) else { return ["写出失败"] }
            actions.append("重建 \(covered) 处遮盖")
            actions.append("被遮页的文字层已去掉")
            return actions
        }

        if let attrs = doc.documentAttributes, !attrs.isEmpty {
            doc.documentAttributes = [:]
            actions.append("清 PDF 属性")
        }
        guard doc.write(to: dst) else { return ["写不出 PDF"] }
        if actions.isEmpty { actions.append("清 PDF 元数据") }
        return actions
    }

    /// 渲染并就地遮盖：和 PDF 的坐标空间同源，不用再做 Y 翻转
    static func redactPage(_ page: PDFPage, dpi: CGFloat = 200) -> (image: CGImage?, covered: Int) {
        let r = page.bounds(for: .mediaBox)
        let scale = dpi / 72
        let w = Int(r.width * scale), h = Int(r.height * scale)
        guard w > 0, h > 0, w * h <= 40_000_000 else { return (nil, 0) }
        guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue) else { return (nil, 0) }
        ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
        ctx.saveGState()
        ctx.scaleBy(x: scale, y: scale)
        page.draw(with: .mediaBox, to: ctx)
        ctx.restoreGState()          // 画完必须还原，否则下面按像素填的矩形会被再乘一次缩放
        guard let raw = ctx.makeImage() else { return (nil, 0) }
        let hits = OCR.hits(in: raw)
        guard !hits.isEmpty else { return (raw, 0) }
        ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        for hit in hits {
            let padX = max(4, CGFloat(w) * 0.006)
            let padY = max(4, CGFloat(h) * 0.004)
            ctx.fill(CGRect(x: hit.rect.minX * CGFloat(w) - padX,
                            y: hit.rect.minY * CGFloat(h) - padY,
                            width: hit.rect.width * CGFloat(w) + padX * 2,
                            height: hit.rect.height * CGFloat(h) + padY * 2))
        }
        return (ctx.makeImage(), hits.count)
    }

    static func renderPage(_ page: PDFPage, dpi: CGFloat) -> CGImage? {
        let r = page.bounds(for: .mediaBox)
        let scale = dpi / 72
        let w = Int(r.width * scale), h = Int(r.height * scale)
        guard w > 0, h > 0, w * h <= 40_000_000 else { return nil }
        guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue) else { return nil }
        ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
        ctx.scaleBy(x: scale, y: scale)
        page.draw(with: .mediaBox, to: ctx)
        return ctx.makeImage()
    }

    // MARK: 执行

    static func officeTarget(_ ext: String) -> String? {
        switch ext {
        case "wps", "doc", "wpt": return "docx"
        case "et", "xls", "ett": return "xlsx"
        case "dps", "ppt", "dpt": return "pptx"
        default: return nil
        }
    }

    static func libreOffice() -> String? {
        let p = "/Applications/LibreOffice.app/Contents/MacOS/soffice"
        return FileManager.default.isExecutableFile(atPath: p) ? p : nil
    }

    /// 调 LibreOffice 无头转换。沙盒化的 WPS 不能从外部驱动，所以用它。
    static func convert(_ src: URL, to target: String, outDir: URL) -> (URL?, String?) {
        guard let bin = libreOffice() else { return (nil, "没找到 LibreOffice，无法转换该格式") }
        let r = Shell.run(bin, ["--headless", "--norestore", "--nolockcheck",
                                "-env:UserInstallation=file:///tmp/jingpan-lo-profile",
                                "--convert-to", target, "--outdir", outDir.path, src.path],
                          timeout: 180)
        if !r.ok { Log.w("convert: soffice 未成功 \(r.out.suffix(120))") }
        let expect = outDir.appendingPathComponent(src.deletingPathExtension().lastPathComponent)
            .appendingPathExtension(target)
        guard FileManager.default.fileExists(atPath: expect.path) else {
            return (nil, "LibreOffice 没能转换这个文件（格式可能不受支持或已损坏）")
        }
        return (expect, nil)
    }

    /// OFD：文字是 XML 节点，直接改；扫描件按 OCR 坐标盖图，再整包重打
    static func cleanOFD(_ src: URL, to dst: URL) -> [String] {
        guard OFD.isOFD(src.path) else { return ["不是标准 OFD"] }
        guard !OFD.hasSignature(src.path) else {
            return ["这个 OFD 带数字签章，改动会让签章失效，未自动处理"]
        }
        var edits: [String: Data] = [:]
        var changedText = 0
        for p in OFD.pages(src.path) {
            guard let xml = Confidential.zipMember(src.path, p.content) else { continue }
            let (newXML, n) = OFD.redactXML(xml)
            if n > 0 {
                edits[p.content] = Data(newXML.utf8)
                changedText += n
            }
        }
        var masked = 0
        for path in OFD.imageEntries(src.path) {
            guard let data = Confidential.zipMemberData(src.path, path),
                  let out = maskImageData(data) else { continue }
            edits[path] = out
            masked += 1
        }
        guard !edits.isEmpty else { return ["没有需要改写的内容"] }
        guard OFD.repack(src: src.path, to: dst.path, edits: edits) else { return ["重打包失败"] }
        var actions: [String] = []
        if changedText > 0 { actions.append("改写 \(changedText) 处文字") }
        if masked > 0 { actions.append("遮盖 \(masked) 张图") }
        return actions
    }

    /// 图片命中才重写；没命中就返回 nil，避免无意义重编码
    static func maskImageData(_ data: Data) -> Data? {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil),
              let img = CGImageSourceCreateImageAtIndex(src, 0, nil) else { return nil }
        let hits = OCR.hits(in: img)
        guard !hits.isEmpty, let covered = cover(img, hits: hits) else { return nil }
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, "public.png" as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(dest, covered, nil)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return out as Data
    }

    /// 产出一份干净副本到 outDir；WPS/旧 Office 先转格式再清理。
    static func produceForReview(file u: URL, outDir: URL, ocr: Bool) -> (url: URL?, actions: [String], error: String?) {
        let ext = u.pathExtension.lowercased()
        if let target = officeTarget(ext) {
            let work = outDir.appendingPathComponent(".conv-" + UUID().uuidString)
            try? FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
            let (converted, err) = convert(u, to: target, outDir: work)
            guard let converted else { return (nil, [], err) }
            let dst = outDir.appendingPathComponent(u.deletingPathExtension().lastPathComponent)
                .appendingPathExtension(target)
            let r = produce(file: converted, to: dst, ocr: ocr)
            try? FileManager.default.removeItem(at: work)
            if let e = r.error { return (nil, r.actions, e) }
            return (dst, r.actions + ["格式转为 \(target)"], nil)
        }
        let dst = outDir.appendingPathComponent(u.lastPathComponent)
        let r = produce(file: u, to: dst, ocr: ocr)
        return (r.error == nil ? dst : nil, r.actions, r.error)
    }

    /// 只产出干净副本，不动原件；返回副本路径
    static func produce(file u: URL, to dst: URL, ocr: Bool) -> (actions: [String], error: String?) {
        let ext = u.pathExtension.lowercased()
        let cap = capability(ext)
        guard cap.ok else { return ([], cap.what) }

        var before = Confidential.Result()
        Confidential.inspectFileForCLI(u, ocr: ocr, into: &before)
        let beforeCritical = before.findings.filter { $0.kind == .classification && $0.level.isReportable }
        if beforeCritical.isEmpty { return ([], "该文件没有国家秘密或工作秘密标志，无需脱密") }

        var actions: [String] = []
        switch ext {
        case "txt", "md", "csv", "json", "xml", "html", "htm", "log":
            guard let text = Confidential.readText(u) else { return ([], "读不出来") }
            try? Data(cleanText(text).utf8).write(to: dst)
            actions = ["遮盖命中内容", "删除密级标志行"]
        case "docx", "xlsx", "pptx", "docm", "xlsm", "pptm":
            let r = cleanOOXML(u, to: dst)
            if let err = r.error { return (r.actions, err) }
            actions = r.actions
        case "jpg", "jpeg", "png", "heic", "tif", "tiff":
            actions = cleanImage(u, to: dst)
        case "pdf":
            actions = cleanPDF(u, to: dst)
        case "ofd":
            actions = cleanOFD(u, to: dst)
        default:
            return ([], cap.what)
        }
        guard FileManager.default.fileExists(atPath: dst.path) else { return (actions, "生成副本失败") }

        // 复检：原来命中的类别必须消失，否则不给「已脱密」这个结论
        var after = Confidential.Result()
        Confidential.inspectFileForCLI(dst, ocr: ocr, into: &after)
        let still = after.findings.filter { $0.kind == .classification && $0.level.isReportable }
        if !still.isEmpty {
            return (actions, "复检没过：" + still.map { $0.kind.rawValue }.joined(separator: "、") + " 仍在")
        }
        return (actions, nil)
    }

    /// 原目录里挑一个不撞名的落点：已有同名副本（上次的脱密结果）就换名，绝不覆盖
    static func freeURL(in dir: URL, preferred: URL) -> URL {
        if !FileManager.default.fileExists(atPath: preferred.path) { return preferred }
        let stem = preferred.deletingPathExtension().lastPathComponent
        let ext = preferred.pathExtension
        var n = 1
        while n <= 99 {
            let name = ext.isEmpty ? "\(stem) (脱密 \(n))" : "\(stem) (脱密 \(n)).\(ext)"
            let candidate = dir.appendingPathComponent(name)
            if !FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            n += 1
        }
        return dir.appendingPathComponent(UUID().uuidString + (ext.isEmpty ? "" : "." + ext))
    }

    /// 处理一个文件：产出干净副本（必要时先转格式）→ 复检 → 原件进回收目录 → 副本回原位
    static func apply(file u: URL, ocr: Bool, trashDir: URL) -> Outcome {
        var out = Outcome(file: u.lastPathComponent)
        let ext = u.pathExtension.lowercased()
        let dir = u.deletingLastPathComponent()

        let work = URL(fileURLWithPath: NSTemporaryDirectory() + "baomi-out-" + UUID().uuidString)
        try? FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        let produced = produceForReview(file: u, outDir: work, ocr: ocr)
        out.actions = produced.actions
        guard let cleanURL = produced.url else {
            out.error = produced.error ?? "生成副本失败"
            return out
        }
        out.verified = true

        // 原件先移走，再放副本：中途失败还能回滚
        try? FileManager.default.createDirectory(at: trashDir, withIntermediateDirectories: true)
        var target = trashDir.appendingPathComponent(u.lastPathComponent)
        if FileManager.default.fileExists(atPath: target.path) {
            let stamp = Int(Date().timeIntervalSince1970)
            target = trashDir.appendingPathComponent(
                u.deletingPathExtension().lastPathComponent + "-\(stamp)." + ext)
        }
        do {
            try transfer(u, target)
            out.trashedTo = target.path
        } catch {
            out.error = "原件移入回收目录失败：\(error.localizedDescription)"
            return out
        }

        let preferred = dir.appendingPathComponent(cleanURL.lastPathComponent)
        let finalURL = freeURL(in: dir, preferred: preferred)
        if finalURL.lastPathComponent != u.lastPathComponent {
            out.newFile = finalURL.lastPathComponent
        }
        do {
            try transfer(cleanURL, finalURL)
        } catch {
            // 回滚也要跨卷安全；回滚失败必须如实说
            do {
                try transfer(target, u)
                out.error = "副本就位失败，已回滚（原件在原位）"
            } catch {
                out.error = "副本就位失败，原件在回收目录：\(target.path)"
            }
            return out
        }
        return out
    }

}

