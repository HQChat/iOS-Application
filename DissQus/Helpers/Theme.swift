//
//  Theme.swift
//  DissQus
//
//  hqchat design system — the "hard-edge" dark aesthetic from the product
//  mockups: green/purple accents, monospace machine labels, encrypted badges,
//  grain + scanline texture, glowing bokeh, and animated audio waveforms.
//
//  Everything here is cross-platform (macOS + iOS) and purely visual — it never
//  touches app logic. Use `HQColor` for the palette, `HQFont` for type, the view
//  modifiers (`.hqScreenBackground()`, `.hqCornerBrackets()`), the reusable
//  components (`HQLogoMark`, `EncryptedBadge`, `Waveform`), and the button styles.
//

import SwiftUI
import CryptoKit
#if os(iOS)
import UIKit
#endif

// MARK: - Color palette

/// The hqchat palette. Names map to the mockup tokens.
enum HQColor {
    // Surfaces
    static let bgTop      = Color(hex: 0x101116)
    static let bgBottom   = Color(hex: 0x16171d)
    static let screen     = Color(hex: 0x070809)   // the "phone screen" black
    static let panel      = Color(hex: 0x0a0b10)

    // Brand greens
    static let green       = Color(hex: 0x16c46e)
    static let greenBright = Color(hex: 0x1bd676)
    static let greenDeep   = Color(hex: 0x0f7d49)

    // Brand violets
    static let purple      = Color(hex: 0x7b2ff7)
    static let purpleLight = Color(hex: 0xa06bff)
    static let purpleSoft  = Color(hex: 0xefe2ff)

    // Warning / caution. Previously hard-coded as 0xffb23b at four call sites
    // and as system `Color.orange` in the banners.
    static let warning     = Color(hex: 0xffb23b)
    static let warningDeep = Color(hex: 0xc47a12)

    // Danger / record
    static let danger      = Color(hex: 0xff5a3c)
    static let dangerDeep  = Color(hex: 0xc41f1f)
    static let dangerLight = Color(hex: 0xff8a72)
    static let record      = Color(hex: 0xff3b30)

    // Text. The ramp is contrast-checked against `bgTop` (#101116) and the
    // standard card fill; every step here clears WCAG AA for body text (4.5:1).
    // `textDim` (3.60) and `textFaint` (3.00) used to fail — and they carried
    // real content: message timestamps and the public-key stamp on every
    // contact row.
    static let textPrimary = Color(hex: 0xeef0f3)   // 16.5:1
    static let textSecond  = Color(hex: 0x9a9ca6)   //  6.9:1
    static let textMuted   = Color(hex: 0x83858f)   //  5.1:1
    static let textDim     = Color(hex: 0x8b8d96)   //  5.6:1 (was 0x6a6c74)
    static let textFaint   = Color(hex: 0x83858f)   //  5.1:1 (was 0x5e6066)

    /// Dark ink for text sitting *on* a brand-green fill (primary buttons,
    /// unread pills, accept). Was a bare `Color(hex: 0x06140c)` at five sites.
    static let onGreen     = Color(hex: 0x06140c)
    /// Body text one step below primary, on cards.
    static let textOnCard  = Color(hex: 0xcdcfd6)
    /// A disabled control's label.
    static let textOff     = Color(hex: 0x4a4b52)
    /// Message text inside an outgoing (green) bubble, and inside an incoming
    /// one. Two of the last raw literals in `Views/`.
    static let inkOnGreenBubble = Color(hex: 0xeafff4)
    static let inkOnGreyBubble  = Color(hex: 0xdfe1e8)
    /// The pale green an "accept" label uses on the incoming-call screen.
    static let greenPale   = Color(hex: 0x7fe6b0)
    /// The two halves of the chromatic-aberration text shadow (`hqChroma`).
    static let chromaWarm  = Color(hex: 0xff005a)
    static let chromaCool  = Color(hex: 0x00d2ff)

    // Hairlines / fills
    static let hairline    = Color.white.opacity(0.08)
    static let fillSoft     = Color.white.opacity(0.04)
}

extension Color {
    /// Hex literal initializer, e.g. `Color(hex: 0x16c46e)`.
    init(hex: UInt32, alpha: Double = 1) {
        self.init(
            .sRGB,
            red:   Double((hex >> 16) & 0xff) / 255,
            green: Double((hex >> 8) & 0xff) / 255,
            blue:  Double(hex & 0xff) / 255,
            opacity: alpha
        )
    }
}

// MARK: - Typography

/// Type, in two voices: monospace for anything machine-ish (keys, timestamps,
/// status, prompts) and a UI sans for prose.
///
/// The numbers passed in are the design's points *at the default text size*.
/// Both functions scale them by the reader's Dynamic Type setting, which
/// nothing in this app used to do: 36 call sites asked for a fixed
/// `.system(size:)`, so raising the system text size changed nothing at all —
/// in a messaging app, that shuts a lot of people out.
///
/// `UIFontMetrics` reads the current content-size category rather than the
/// SwiftUI environment, so the root view keys itself on `dynamicTypeSize` (see
/// ContentView) to rebuild when the setting changes.
enum HQFont {
    /// Monospace machine label (SF Mono substitute for JetBrains Mono).
    static func mono(_ size: CGFloat, weight: Font.Weight = .medium) -> Font {
        .system(size: scaled(size), weight: weight, design: .monospaced)
    }
    /// UI text (SF Pro substitute for Hanken Grotesk).
    static func ui(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: scaled(size), weight: weight)
    }

    /// A design point size, scaled for the reader. Also the way to scale a
    /// *frame* that has to keep pace with the text inside it.
    static func scaled(_ size: CGFloat) -> CGFloat {
        #if os(iOS)
        return UIFontMetrics.default.scaledValue(for: size)
        #else
        return size
        #endif
    }
}

// MARK: - Tap targets

extension View {
    /// Grow the hit area to Apple's 44×44 minimum without growing the artwork.
    /// Icon-only controls in this app were drawn at 30–38pt, which looks right
    /// and misses often.
    func hqTapTarget(_ side: CGFloat = 44) -> some View {
        frame(minWidth: side, minHeight: side)
            .contentShape(Rectangle())
    }
}

// MARK: - Screen background

/// The full hqchat backdrop: vertical gradient, two blurred bokeh glows
/// (green + violet), scanlines and a vignette. Drop behind any screen with
/// `.hqScreenBackground()`.
struct HQScreenBackground: View {
    var animated: Bool = true
    /// Four animations in this app ran `repeatForever` with nothing to turn
    /// them off. Perpetual motion is exactly what Reduce Motion is for.
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pulse = false

    var body: some View {
        ZStack {
            LinearGradient(colors: [HQColor.bgTop, HQColor.bgBottom],
                           startPoint: .top, endPoint: .bottom)

            GeometryReader { geo in
                let w = geo.size.width
                let h = geo.size.height
                ZStack {
                    bokeh(HQColor.green)
                        .frame(width: w * 1.1, height: w * 1.1)
                        .position(x: w * 0.12, y: h * 0.08)
                        .scaleEffect(pulse ? 1.08 : 1)
                    bokeh(HQColor.purple)
                        .frame(width: w * 1.1, height: w * 1.1)
                        .position(x: w * 0.92, y: h * 0.95)
                        .scaleEffect(pulse ? 1.05 : 1)
                }
                .blur(radius: 90)
                .opacity(0.42)
            }

            Scanlines()
                .opacity(0.62)
                .blendMode(.multiply)
                .allowsHitTesting(false)

            // Vignette
            RadialGradient(colors: [.clear, .black.opacity(0.65)],
                           center: .center, startRadius: 120, endRadius: 520)
                .allowsHitTesting(false)
        }
        .ignoresSafeArea()
        .onAppear {
            guard animated, !reduceMotion else { return }
            withAnimation(.easeInOut(duration: 11).repeatForever(autoreverses: true)) {
                pulse = true
            }
        }
    }

    private func bokeh(_ color: Color) -> some View {
        Circle().fill(
            RadialGradient(colors: [color, color.opacity(0)],
                           center: .center, startRadius: 0, endRadius: 220)
        )
    }
}

/// Lightweight repeating scanline texture drawn with a Canvas (static, cheap).
struct Scanlines: View {
    var body: some View {
        Canvas { ctx, size in
            var y: CGFloat = 0
            let line = Color.black.opacity(0.30)
            while y < size.height {
                ctx.fill(Path(CGRect(x: 0, y: y, width: size.width, height: 1)),
                         with: .color(line))
                y += 3
            }
        }
        .allowsHitTesting(false)
    }
}

extension View {
    /// Places the hqchat backdrop behind this view and forces dark text colors.
    func hqScreenBackground(animated: Bool = true) -> some View {
        self.background(HQScreenBackground(animated: animated))
            .foregroundColor(HQColor.textPrimary)
    }
}

// MARK: - Prompt header

/// A dashed ASCII rule — the separator this UI uses instead of `Divider`.
struct HQRule: View {
    var color: Color = HQColor.hairline
    var body: some View {
        Line()
            .stroke(style: StrokeStyle(lineWidth: 1, dash: [3, 3]))
            .foregroundColor(color)
            .frame(height: 1)
    }

    private struct Line: Shape {
        func path(in rect: CGRect) -> Path {
            var p = Path()
            p.move(to: CGPoint(x: 0, y: rect.midY))
            p.addLine(to: CGPoint(x: rect.maxX, y: rect.midY))
            return p
        }
    }
}

/// The top bar every screen except a conversation wears: a shell prompt naming
/// the app and the screen, a blinking cursor, and whatever status the caller
/// hands it.
///
/// It replaces `.navigationTitle`, which put a system-styled sentence-case title
/// on screens that are otherwise a terminal — and, on Contacts, said the word
/// "contacts" twice because the list already has a section by that name.
struct HQPromptHeader<Trailing: View>: View {
    /// The screen, as a path segment: `chats`, `contacts`, `settings`. The only
    /// thing that differs between screens — everything else here is identical
    /// by construction, so the three tabs cannot drift apart.
    let path: String
    @ViewBuilder var trailing: () -> Trailing

    private let size: CGFloat = 16

    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 0) {
                Text("hqchat")
                    .font(HQFont.mono(size, weight: .bold))
                    .foregroundColor(HQColor.green)
                Text(":~/")
                    .font(HQFont.mono(size))
                    .foregroundColor(HQColor.textDim)
                Text(path)
                    .font(HQFont.mono(size, weight: .semibold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .foregroundColor(HQColor.purpleLight)
                Text("$")
                    .font(HQFont.mono(size))
                    .foregroundColor(HQColor.textDim)
                Text(" \u{2588}")
                    .font(HQFont.mono(size))
                    .foregroundColor(HQColor.green)
                    .modifier(BlinkModifier())

                Spacer(minLength: 8)

                trailing()
            }
            .padding(.horizontal, 16)

            HQRule()
        }
        .padding(.top, 8)
        .padding(.bottom, 2)
    }
}

extension HQPromptHeader where Trailing == EmptyView {
    init(path: String) {
        self.init(path: path) { EmptyView() }
    }
}

/// The header a *pushed* screen wears: the same prompt, one path segment
/// deeper, with a `[<]` back control in place of the tab roots' status chips.
///
/// Pushed screens used to fall back to a stock nav bar with a sentence-case SF
/// title, so walking from Settings into Account visibly changed design language
/// mid-stack. Sheets are deliberately left alone — a modal is a system surface
/// and should look like one.
struct HQSubScreenHeader: View {
    /// Full path, e.g. `settings/account`.
    let path: String
    let onBack: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 12) {
                Button(action: onBack) {
                    Text("[<]")
                        .font(HQFont.mono(15, weight: .bold))
                        .foregroundColor(HQColor.green)
                        .hqTapTarget()
                }
                .buttonStyle(.plain)
                .accessibilityLabel("back")

                HStack(spacing: 0) {
                    Text("hqchat")
                        .font(HQFont.mono(15, weight: .bold))
                        .foregroundColor(HQColor.green)
                    Text(":~/")
                        .font(HQFont.mono(15))
                        .foregroundColor(HQColor.textDim)
                    Text(path)
                        .font(HQFont.mono(15, weight: .semibold))
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                        .foregroundColor(HQColor.purpleLight)
                    Text("$")
                        .font(HQFont.mono(15))
                        .foregroundColor(HQColor.textDim)
                }
                .accessibilityAddTraits(.isHeader)

                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)

            HQRule()
        }
        .padding(.top, 6)
        .padding(.bottom, 2)
    }
}

// MARK: - Logo mark

/// The hqchat 3×3 grid logo: a dark rounded tile with two lit cells
/// (green top-right, violet bottom-left) over soft brand glows.
struct HQLogoMark: View {
    var size: CGFloat = 56
    var lit: [Int: Color] = [2: HQColor.green, 6: HQColor.purple]   // 3×3 indices

    var body: some View {
        let corner = size * 0.21
        let cell = size * 0.62 / 3
        let gap = cell * 0.18
        ZStack {
            RoundedRectangle(cornerRadius: corner, style: .continuous)
                .fill(HQColor.screen)
                .overlay(
                    RoundedRectangle(cornerRadius: corner, style: .continuous)
                        .stroke(Color.white.opacity(0.06), lineWidth: 1)
                )
            // brand glows
            Circle().fill(RadialGradient(colors: [HQColor.green.opacity(0.7), .clear],
                                         center: .center, startRadius: 0, endRadius: size * 0.5))
                .frame(width: size, height: size)
                .blur(radius: size * 0.18)
                .offset(x: -size * 0.18, y: -size * 0.18)
            Circle().fill(RadialGradient(colors: [HQColor.purple.opacity(0.7), .clear],
                                         center: .center, startRadius: 0, endRadius: size * 0.5))
                .frame(width: size, height: size)
                .blur(radius: size * 0.18)
                .offset(x: size * 0.18, y: size * 0.18)

            LazyVGrid(columns: Array(repeating: GridItem(.fixed(cell), spacing: gap), count: 3), spacing: gap) {
                ForEach(0..<9, id: \.self) { i in
                    RoundedRectangle(cornerRadius: cell * 0.18)
                        .fill(lit[i] == nil ? Color.white.opacity(0.07) : Color.clear)
                        .overlay {
                            if let c = lit[i] {
                                RoundedRectangle(cornerRadius: cell * 0.18)
                                    .fill(RadialGradient(colors: [.white, c],
                                                         center: .init(x: 0.42, y: 0.36),
                                                         startRadius: 0, endRadius: cell))
                                    .shadow(color: c.opacity(0.9), radius: cell * 0.4)
                            }
                        }
                        .frame(width: cell, height: cell)
                }
            }
            .frame(width: cell * 3 + gap * 2, height: cell * 3 + gap * 2)
        }
        .frame(width: size, height: size)
    }
}

/// The "hq**chat**" wordmark (light "hq", bold "chat").
struct HQWordmark: View {
    var size: CGFloat = 34
    var body: some View {
        (Text("hq").fontWeight(.light) + Text("chat").fontWeight(.bold))
            .font(.system(size: size))
            .tracking(-1)
            .foregroundColor(.white)
    }
}

// MARK: - Avatar

/// A rounded-rect ("squircle") avatar showing a contact's initials over the
/// hqchat panel, with a brand glow and optional online dot. Used on the call
/// and chat screens.
struct HQAvatar: View {
    let name: String
    var size: CGFloat = 128
    var glow: Color = HQColor.purple
    var isOnline: Bool? = nil

    private var initials: String {
        let parts = name
            .replacingOccurrences(of: "_", with: " ")
            .replacingOccurrences(of: ".", with: " ")
            .split(separator: " ")
        let letters = parts.prefix(2).compactMap { $0.first }
        let s = String(letters).uppercased()
        return s.isEmpty ? "?" : s
    }

    var body: some View {
        let corner = size * 0.17
        ZStack(alignment: .bottomTrailing) {
            RoundedRectangle(cornerRadius: corner, style: .continuous)
                .fill(HQColor.panel)
                .overlay(
                    RoundedRectangle(cornerRadius: corner, style: .continuous)
                        .fill(RadialGradient(colors: [glow.opacity(0.5), .clear],
                                             center: .init(x: 0.5, y: 0.4),
                                             startRadius: 0, endRadius: size * 0.7))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: corner, style: .continuous)
                        .stroke(Color.white.opacity(0.08), lineWidth: 1)
                )
                .overlay(
                    Text(initials)
                        .font(.system(size: size * 0.34, weight: .semibold))
                        .foregroundColor(.white)
                )
                .frame(width: size, height: size)
                .shadow(color: glow.opacity(0.6), radius: size * 0.35, y: 4)

            if let isOnline {
                Circle()
                    .fill(isOnline ? HQColor.green : Color.gray)
                    .frame(width: size * 0.18, height: size * 0.18)
                    .overlay(Circle().stroke(HQColor.screen, lineWidth: size * 0.03))
                    .shadow(color: (isOnline ? HQColor.green : .clear).opacity(0.8), radius: 6)
                    .offset(x: -size * 0.04, y: -size * 0.04)
            }
        }
        .frame(width: size, height: size)
    }
}

/// Short display fingerprint of a public key (e.g. "7f3a 9c21 ee04 b8d3").
enum HQFingerprint {
    static func short(_ publicKey: Data) -> String {
        let hash = Array(SHA256.hash(data: publicKey)).prefix(8)
        let hex = hash.map { String(format: "%02x", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map {
            let start = hex.index(hex.startIndex, offsetBy: $0)
            let end = hex.index(start, offsetBy: 4)
            return String(hex[start..<end])
        }.joined(separator: " ")
    }
}

// MARK: - Encrypted badge

/// A monospace "· encrypted ·" pill used across calls and the unlock screen.
struct EncryptedBadge: View {
    var text: String
    var tint: Color = HQColor.green
    var icon: String = "lock.fill"

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 10, weight: .bold))
            Text(text.uppercased())
                .font(HQFont.mono(10, weight: .semibold))
                .tracking(2)
        }
        .foregroundColor(tint)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(tint.opacity(0.08))
        .overlay(Rectangle().stroke(tint.opacity(0.45), lineWidth: 1))
        .clipShape(Rectangle())
    }
}

// MARK: - Waveform

/// A static or live audio waveform of vertical bars. Bars before
/// `playedFraction` use `tint`; the rest are dim. Set `animated` for the live
/// recording / in-call pulse.
struct Waveform: View {
    var count: Int = 28
    var tint: Color = HQColor.green
    var playedFraction: Double = 1
    var animated: Bool = false
    var height: CGFloat = 30
    var spacing: CGFloat = 2

    // Deterministic per-bar heights so the shape is stable across redraws.
    private func barHeight(_ i: Int) -> CGFloat {
        var seed = UInt64(i &* 2654435761 &+ 0x9e3779b9)
        seed ^= seed >> 13; seed = seed &* 0x5bd1e995; seed ^= seed >> 15
        let frac = Double(seed % 1000) / 1000.0
        return 0.28 + frac * 0.72
    }

    var body: some View {
        GeometryReader { geo in
            let totalSpacing = spacing * CGFloat(count - 1)
            let barW = max(1.5, (geo.size.width - totalSpacing) / CGFloat(count))
            HStack(alignment: .center, spacing: spacing) {
                ForEach(0..<count, id: \.self) { i in
                    let played = Double(i) / Double(count) < playedFraction
                    WaveBar(width: barW,
                            maxHeight: height,
                            factor: barHeight(i),
                            color: played ? tint : Color.white.opacity(0.2),
                            animated: animated,
                            delay: Double(i) * 0.045)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
        }
        .frame(height: height)
    }
}

private struct WaveBar: View {
    let width: CGFloat
    let maxHeight: CGFloat
    let factor: CGFloat
    let color: Color
    let animated: Bool
    let delay: Double
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var phase: CGFloat = 1

    var body: some View {
        Capsule(style: .continuous)
            .fill(color)
            .frame(width: width, height: maxHeight * factor * (animated ? phase : 1))
            .onAppear {
                guard animated, !reduceMotion else { return }
                phase = 0.32
                withAnimation(.easeInOut(duration: 0.85).repeatForever(autoreverses: true).delay(delay)) {
                    phase = 1
                }
            }
    }
}

// MARK: - Day separator

/// `──── today ────`, drawn between messages when the calendar day changes.
/// Reads as a mono rule rather than a pill, matching the app's own chrome.
struct DaySeparator: View {
    let text: String

    var body: some View {
        HStack(spacing: 10) {
            HQRule()
            Text(text)
                .font(HQFont.mono(10.5, weight: .semibold))
                .tracking(1.2)
                .foregroundColor(HQColor.textMuted)
                .fixedSize()
            HQRule()
        }
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }
}

// MARK: - Blink

/// Blinks a view's opacity (used for the recording "REC" dot).
struct BlinkModifier: ViewModifier {
    /// When false the content renders normally. Lets a caller keep the modifier
    /// in place while only some states should pulse.
    var active: Bool = true
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var on = true

    func body(content: Content) -> some View {
        content
            .opacity(active && !on ? 0.15 : 1)
            .onAppear {
                guard active, !reduceMotion else { return }
                withAnimation(.easeInOut(duration: 0.5).repeatForever(autoreverses: true)) {
                    on = false
                }
            }
    }
}

/// A one-shot flicker, fired when a value changes — the connection state
/// snapping between codes, rather than crossfading politely.
struct HQGlitch<V: Equatable>: ViewModifier {
    let value: V
    @State private var opacity: Double = 1

    func body(content: Content) -> some View {
        content
            .opacity(opacity)
            .onChange(of: value) { _, _ in
                opacity = 0.15
                withAnimation(.easeOut(duration: 0.28)) { opacity = 1 }
            }
    }
}

extension View {
    /// Flicker this view whenever `value` changes.
    func hqGlitch<V: Equatable>(on value: V) -> some View {
        modifier(HQGlitch(value: value))
    }
}

// MARK: - Swipe navigation

#if os(iOS)
/// Horizontal swipe as a way to move around, alongside the taps that already do
/// it. Before this, the only way between tabs was the tab bar and the only way
/// out of a conversation was the `[<]` glyph in its header — both fine, both a
/// reach on a large phone, and neither what a thumb tries first.
///
/// Deliberately conservative thresholds: the gesture is `simultaneous`, so it
/// runs alongside list scrolling and row swipe-actions rather than stealing from
/// them, and it only fires on a long, decidedly horizontal drag. A short or
/// diagonal drag belongs to whatever is underneath.
struct HQSwipeNavigation: ViewModifier {
    /// Swipe right — the "back" direction in every left-to-right iOS app.
    var onBack: (() -> Void)?
    /// Swipe left.
    var onForward: (() -> Void)?

    /// How far the finger must travel horizontally before this counts.
    private let distance: CGFloat = 90
    /// …and how little it may wander vertically, so a scroll is never mistaken
    /// for a swipe.
    private let drift: CGFloat = 55

    func body(content: Content) -> some View {
        content.simultaneousGesture(
            DragGesture(minimumDistance: 24, coordinateSpace: .local)
                .onEnded { value in
                    let dx = value.translation.width
                    let dy = value.translation.height
                    guard abs(dx) >= distance, abs(dy) <= drift, abs(dx) > abs(dy) * 2 else { return }
                    if dx > 0 { onBack?() } else { onForward?() }
                }
        )
    }
}

extension View {
    /// Swipe right / left to move between sibling screens, or out of this one.
    func hqSwipeNavigation(onBack: (() -> Void)? = nil,
                           onForward: (() -> Void)? = nil) -> some View {
        modifier(HQSwipeNavigation(onBack: onBack, onForward: onForward))
    }
}
#endif

// MARK: - Corner brackets (selected card)

/// Four neon corner brackets, as on the selected profile card.
struct CornerBrackets: View {
    var color: Color = HQColor.green
    var length: CGFloat = 11
    var thickness: CGFloat = 2

    var body: some View {
        GeometryReader { _ in
            ZStack {
                bracket(.topLeading)
                bracket(.topTrailing)
                bracket(.bottomLeading)
                bracket(.bottomTrailing)
            }
        }
        .allowsHitTesting(false)
    }

    private func bracket(_ corner: Alignment) -> some View {
        let isTop = corner == .topLeading || corner == .topTrailing
        let isLeading = corner == .topLeading || corner == .bottomLeading
        return ZStack(alignment: corner) {
            Color.clear
            VStack {
                if !isTop { Spacer(minLength: 0) }
                HStack {
                    if !isLeading { Spacer(minLength: 0) }
                    Path { p in
                        // horizontal arm
                        p.move(to: CGPoint(x: isLeading ? 0 : length, y: isTop ? 0 : thickness))
                        p.addLine(to: CGPoint(x: isLeading ? length : 0, y: isTop ? 0 : thickness))
                    }
                    .stroke(color, lineWidth: thickness)
                    .frame(width: length, height: length)
                    .overlay(
                        Path { p in
                            p.move(to: CGPoint(x: isLeading ? thickness : length - thickness, y: isTop ? 0 : length))
                            p.addLine(to: CGPoint(x: isLeading ? thickness : length - thickness, y: isTop ? length : 0))
                        }
                        .stroke(color, lineWidth: thickness)
                    )
                    if isLeading { Spacer(minLength: 0) }
                }
                if isTop { Spacer(minLength: 0) }
            }
        }
    }
}

extension View {
    /// Overlays neon corner brackets (selected state).
    func hqCornerBrackets(_ color: Color = HQColor.green, show: Bool = true) -> some View {
        overlay { if show { CornerBrackets(color: color) } }
    }
}

// MARK: - Button styles

/// Solid green-gradient primary button (dark text).
struct HQPrimaryButtonStyle: ButtonStyle {
    var height: CGFloat = 48
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.ui(15, weight: .bold))
            .foregroundColor(HQColor.onGreen)
            .frame(maxWidth: .infinity, minHeight: height)
            .background(LinearGradient(colors: [HQColor.greenBright, HQColor.greenDeep],
                                       startPoint: .topLeading, endPoint: .bottomTrailing))
            .clipShape(Rectangle())
            .overlay(Rectangle().stroke(HQColor.green.opacity(0.75), lineWidth: 1))
            .shadow(color: HQColor.green.opacity(0.5), radius: 14, y: 2)
            .opacity(configuration.isPressed ? 0.8 : 1)
    }
}

/// Green→violet gradient "enter" button (white text).
struct HQGradientButtonStyle: ButtonStyle {
    var height: CGFloat = 50
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.ui(15, weight: .bold))
            .foregroundColor(.white)
            .frame(maxWidth: .infinity, minHeight: height)
            .background(LinearGradient(colors: [HQColor.green, HQColor.purple],
                                       startPoint: .topLeading, endPoint: .bottomTrailing))
            .clipShape(Rectangle())
            .overlay(Rectangle().stroke(HQColor.purple.opacity(0.6), lineWidth: 1))
            .shadow(color: HQColor.purple.opacity(0.55), radius: 16, y: 2)
            .opacity(configuration.isPressed ? 0.8 : 1)
    }
}

/// Outlined neutral button.
struct HQSecondaryButtonStyle: ButtonStyle {
    var tint: Color = HQColor.textPrimary
    var height: CGFloat = 44
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.mono(13.5, weight: .semibold))
            .foregroundColor(tint)
            .frame(maxWidth: .infinity, minHeight: height)
            .background(Color.white.opacity(0.07))
            .clipShape(Rectangle())
            .overlay(Rectangle().stroke(Color.white.opacity(0.28), lineWidth: 1))
            .opacity(configuration.isPressed ? 0.7 : 1)
    }
}

/// Danger button (red). A destructive control has to be *seen* first and
/// hesitated over second: the old 6%-fill / 30%-border version read as disabled
/// text on the dark backdrop, so "delete my account" was nearly invisible.
struct HQDangerButtonStyle: ButtonStyle {
    var height: CGFloat = 44
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.mono(13.5, weight: .bold))
            .foregroundColor(HQColor.dangerLight)
            .frame(maxWidth: .infinity, minHeight: height)
            .background(Color(hex: 0x3a0f0a))
            .clipShape(Rectangle())
            .overlay(Rectangle().stroke(HQColor.danger, lineWidth: 1))
            .opacity(configuration.isPressed ? 0.7 : 1)
    }
}

/// An inline action inside a card — the `[change]` next to your username. Bare
/// coloured text read as a label, not something you could press.
struct HQInlineActionStyle: ButtonStyle {
    var tint: Color = HQColor.green
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.mono(12, weight: .bold))
            .foregroundColor(tint)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(tint.opacity(0.10))
            .overlay(Rectangle().stroke(tint.opacity(0.55), lineWidth: 1))
            .opacity(configuration.isPressed ? 0.6 : 1)
    }
}

// MARK: - Form field

/// A monospace section label (e.g. "PROFILE NAME") used above inputs. `tint`
/// carries the section's accent so a label and its card read as one unit.
struct HQFieldLabel: View {
    let text: String
    var tint: Color = HQColor.textDim
    var body: some View {
        Text(text.uppercased())
            .font(HQFont.mono(11, weight: .semibold))
            .tracking(1.5)
            .foregroundColor(tint)
    }
}

/// A dark hard-edge text field with an optional leading green accent bar / "@"
/// prefix, matching the onboarding mockups.
struct HQTextField: View {
    let placeholder: String
    @Binding var text: String
    var monospaced: Bool = false
    var prefix: String? = nil
    var accent: Bool = false

    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 2) {
            // A caret rather than a rail: the field reads as a line you type on.
            Text(focused ? "\u{25B8}" : "\u{25B9}")
                .font(HQFont.mono(13, weight: .bold))
                .foregroundColor(focused ? HQColor.greenBright : HQColor.textDim)
                .padding(.trailing, 8)
                .shadow(color: focused ? HQColor.green.opacity(0.8) : .clear, radius: 4)

            if let prefix {
                Text(prefix)
                    .font(monospaced ? HQFont.mono(15) : HQFont.ui(15))
                    .foregroundColor(HQColor.textFaint)
            }
            field
                .font(monospaced ? HQFont.mono(15) : HQFont.ui(15))
                .foregroundColor(HQColor.textPrimary)
                .textFieldStyle(.plain)
                .focused($focused)
        }
        .padding(.horizontal, 14)
        // Scales with the text inside it — a fixed 50 clipped its own field at
        // larger text sizes.
        .frame(minHeight: HQFont.scaled(50))
        // Boxed on four sides, every input looked like a disabled panel. One
        // underline that lights on focus says "type here" and leaves the
        // surrounding card borders to do their own job.
        .background(Color.white.opacity(focused ? 0.055 : 0.03))
        .clipShape(Rectangle())
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(focused ? HQColor.green : Color.white.opacity(0.16))
                .frame(height: focused ? 1.5 : 1)
                .shadow(color: focused ? HQColor.green.opacity(0.6) : .clear, radius: 5)
        }
        .animation(.easeOut(duration: 0.16), value: focused)
    }

    @ViewBuilder private var field: some View {
        #if os(iOS)
        TextField(placeholder, text: $text)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
        #else
        TextField(placeholder, text: $text)
        #endif
    }
}

// MARK: - Surface card

extension View {
    /// A standard hqchat surface panel: faint fill, hairline border.
    ///
    /// `accent` colours the border and adds a lit left rail. Settings uses one
    /// accent per section — identity, security, danger — so a screen of stacked
    /// grey cards stops reading as one undifferentiated wall.
    func hqCard(selected: Bool = false,
                cornerRadius: CGFloat = 0,
                padding: CGFloat = 14,
                accent: Color? = nil) -> some View {
        self
            .padding(padding)
            .background(selected ? HQColor.green.opacity(0.06)
                        : (accent?.opacity(0.05) ?? HQColor.fillSoft))
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius))
            .overlay(alignment: .leading) {
                if let accent {
                    Rectangle()
                        .fill(accent)
                        .frame(width: 2)
                        .shadow(color: accent.opacity(0.7), radius: 4)
                }
            }
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .stroke(selected ? HQColor.green.opacity(0.55)
                            : (accent?.opacity(0.40) ?? Color.white.opacity(0.08)), lineWidth: 1)
            )
    }
}
