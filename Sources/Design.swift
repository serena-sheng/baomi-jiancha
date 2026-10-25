// 与「净盘」同一套视觉语言：色 8 个、字号 5 档、间距 8/16、一个强调色、
// 状态只出现在 ≤2pt 的线、6pt 圆点与图标着色上，面永不染色。
import SwiftUI
import AppKit

func dyn(_ light: UInt32, _ dark: UInt32, _ a: CGFloat = 1) -> Color {
    Color(nsColor: NSColor(name: nil) { app in
        let isDark = app.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
        let hex = isDark ? dark : light
        return NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
                       green: CGFloat((hex >> 8) & 0xFF) / 255,
                       blue: CGFloat(hex & 0xFF) / 255,
                       alpha: a)
    })
}

enum T {
    static let ink    = dyn(0x1D1D1F, 0xF5F5F7)
    static let ink2   = dyn(0x5A5A61, 0xA6A6AD)
    static let ink3   = dyn(0x67676F, 0xA0A0A6)   // 深色由 #949499 提到 4.6:1 以上
    static let hair   = dyn(0x000000, 0xFFFFFF, 0.08)
    static let track  = dyn(0x000000, 0xFFFFFF, 0.06)
    static let accent = dyn(0x0066CC, 0x7FA9B8)   // 深色不压白字：#7FA9B8 配 onAccent 深字 6.8:1
    static let onAccent = dyn(0xFFFFFF, 0x1B1B1D) // 深色主按钮是亮底深字，白字压亮蓝只有 2.5:1
    static let ok     = dyn(0x1B7A34, 0x32D74B)
    static let warn   = dyn(0xB25000, 0xFF9F0A)

    static let padH: CGFloat = 16
    static let padTop: CGFloat = 16
    static let padBottom: CGFloat = 16
    static let radius: CGFloat = 12
    static let ctrl: CGFloat = 6
    static let gap: CGFloat = 8
    static let block: CGFloat = 16
    static let barH: CGFloat = 2
    static let dot: CGFloat = 6
    static let btnH: CGFloat = 32
    static let ghostH: CGFloat = 28
    static let btnPadH: CGFloat = 16
}

extension Font {
    static let jpD = Font.system(size: 34, weight: .semibold).monospacedDigit()
    static let jpT = Font.system(size: 16, weight: .semibold)
    static let jpL = Font.system(size: 20, weight: .semibold)
    static let jpB = Font.system(size: 13)
    static let jpM = Font.system(size: 13, weight: .medium)
    static let jpP = Font.system(size: 13, weight: .semibold)
    static let jpC = Font.system(size: 12).monospacedDigit()
}

struct JPHairline: View {
    var body: some View { Rectangle().fill(T.hair).frame(height: 0.5) }
}

/// 6pt 圆点：状态不只靠颜色，旁边永远有字
struct JPDot: View {
    var color: Color
    var body: some View { Circle().fill(color).frame(width: T.dot, height: T.dot) }
}

struct JPBar: View {
    var value: Double
    var tint: Color = T.accent
    /// 总量未知（扫描期）：扫光往返，不伪造百分比
    var indeterminate = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(T.track)
                if indeterminate {
                    if reduceMotion {
                        Capsule().fill(tint.opacity(0.55)).frame(width: g.size.width * 0.3)
                    } else {
                        TimelineView(.animation(minimumInterval: 1.0 / 60.0)) { ctx in
                            let t = ctx.date.timeIntervalSinceReferenceDate
                            let phase = (t.truncatingRemainder(dividingBy: 1.2)) / 1.2
                            Capsule().fill(tint.opacity(0.7))
                                .frame(width: max(24, g.size.width * 0.28))
                                .offset(x: (g.size.width + 40) * CGFloat(phase) - 40)
                        }
                    }
                } else {
                    Capsule().fill(tint)
                        .frame(width: max(0, min(1, value)) * g.size.width)
                        .animation(.easeOut(duration: 0.18), value: value)
                }
            }
        }
        .frame(height: T.barH)
    }
}

enum JPKind { case primary, ghost }

struct JPButton: View {
    var title: String
    var kind: JPKind = .ghost
    var enabled = true
    /// 行内按钮：20pt 高，不把行撑高
    var compact = false
    var action: () -> Void
    @State private var hover = false

    private var fg: Color {
        guard enabled else { return T.ink3 }
        switch kind {
        case .primary: return .white
        case .ghost:   return hover ? T.ink : T.ink2
        }
    }

    private var bg: Color {
        switch kind {
        case .primary: return enabled ? T.accent : T.track.opacity(0.5)
        case .ghost:   return .clear
        }
    }

    var body: some View {
        Button(action: { if enabled { action() } }) {
            Text(title)
                .font(kind == .ghost ? .jpM : .jpP)
                .foregroundStyle(fg)
                .lineLimit(1)
                .fixedSize()
                .padding(.horizontal, kind == .ghost ? 0 : T.btnPadH)
                .frame(minHeight: compact ? 20 : (kind == .ghost ? T.ghostH : T.btnH))
                .background(
                    RoundedRectangle(cornerRadius: T.ctrl).fill(bg)
                        .overlay(
                            RoundedRectangle(cornerRadius: T.ctrl).fill(
                                Color.white.opacity(kind == .primary && hover && enabled ? 0.06 : 0))
                        )
                )
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .animation(.easeOut(duration: 0.12), value: hover)
        .opacity(enabled ? 1 : 0.45)
        .allowsHitTesting(enabled)
    }
}
