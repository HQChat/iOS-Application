//
//  StatusPresentation.swift
//  DissQus
//
//  Shared banner / empty-state / error presentation.
//
//  Before this existed each view carried its own `@State errorMessage` plus a
//  copy-pasted `.alert("Error", ...)`, the two payment banners were styled
//  differently from each other, and the empty states were duplicated inline.
//  Everything user-facing about status now comes from here.
//

import SwiftUI

// MARK: - Banner

/// A full-width status strip. Sits above content rather than covering it, so a
/// degraded connection is visible without blocking the app.
struct HQBanner: View {
    enum Kind {
        case offline
        case reconnecting
        case warning
        case error

        var tint: Color {
            switch self {
            case .offline: return HQColor.textSecond
            case .reconnecting: return HQColor.warning
            case .warning: return HQColor.warning
            case .error: return HQColor.danger
            }
        }

        var icon: String {
            switch self {
            case .offline: return "wifi.slash"
            case .reconnecting: return "arrow.triangle.2.circlepath"
            case .warning: return "exclamationmark.triangle.fill"
            case .error: return "exclamationmark.octagon.fill"
            }
        }

        /// Only the reconnecting state pulses — a static warning that blinks
        /// reads as an emergency.
        var pulses: Bool {
            if case .reconnecting = self { return true }
            return false
        }
    }

    let kind: Kind
    let text: String
    var actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: kind.icon)
                .accessibilityHidden(true)
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(kind.tint)
                .modifier(BlinkModifier(active: kind.pulses))

            Text(text)
                .font(HQFont.ui(12, weight: .medium))
                .foregroundColor(HQColor.textPrimary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)

            Spacer(minLength: 8)

            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .font(HQFont.mono(11, weight: .semibold))
                    .foregroundColor(kind.tint)
                    .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(kind.tint.opacity(0.10))
        .overlay(alignment: .bottom) {
            Rectangle().fill(kind.tint.opacity(0.30)).frame(height: 1)
        }
        .transition(.move(edge: .top).combined(with: .opacity))
    }
}

// MARK: - Empty state

/// The "nothing here yet" screen, anchored on the app mark. Replaces four
/// hand-rolled variants, two of which ignored the theme entirely.
struct HQEmptyState: View {
    var title: String
    var message: String
    /// Shown instead of `HQLogoMark` when set — for narrower contexts like
    /// "no search results", where the full mark is too heavy.
    var systemImage: String?
    var actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        VStack(spacing: 14) {
            if let systemImage {
                Image(systemName: systemImage)
                    .accessibilityHidden(true)
                    .font(.system(size: 30, weight: .light))
                    .foregroundColor(HQColor.textDim)
            } else {
                HQLogoMark(size: 54)
                    .opacity(0.55)
            }

            VStack(spacing: 5) {
                Text(title)
                    .font(HQFont.ui(15, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)

                Text(message)
                    .font(HQFont.ui(13))
                    .foregroundColor(HQColor.textMuted)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(HQPrimaryButtonStyle())
                    .padding(.top, 4)
                    .frame(maxWidth: 240)
            }
        }
        .padding(.horizontal, 32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Error alert

/// Presents an `AppError` as an alert, with a retry button when retrying could
/// plausibly help. Use instead of a per-view `.alert("Error", ...)`.
struct HQErrorAlert: ViewModifier {
    @Binding var error: AppError?
    var onRetry: (() -> Void)?

    func body(content: Content) -> some View {
        content.alert(
            error?.title ?? "Something went wrong",
            isPresented: Binding(
                get: { error != nil },
                set: { if !$0 { error = nil } }
            ),
            presenting: error
        ) { presented in
            if presented.isRetryable, let onRetry {
                Button("Try again") {
                    error = nil
                    onRetry()
                }
                Button("Dismiss", role: .cancel) { error = nil }
            } else {
                Button("OK", role: .cancel) { error = nil }
            }
        } message: { presented in
            Text(presented.userMessage)
        }
    }
}

extension View {
    /// Standard error presentation. `onRetry` is offered only for errors where
    /// retrying makes sense (see `AppError.isRetryable`).
    func hqError(_ error: Binding<AppError?>, onRetry: (() -> Void)? = nil) -> some View {
        modifier(HQErrorAlert(error: error, onRetry: onRetry))
    }
}

// MARK: - App-wide status banners

/// Status that is true of the whole session, wherever the user happens to be.
/// Rendered once at the root beside `ConnectionBanner`, so neither platform
/// shell has to remember to carry it.
///
/// It used to live inside `RootTabView`, which is `#if os(iOS)` — so on macOS a
/// refused handle set the flag, `SettingsView` suppressed its own prompt
/// because of it, and nothing on screen ever said why nobody could add you.
struct AppStatusBanners: View {
    @ObservedObject var appState: AppState

    var body: some View {
        // The server says it is mid-change. Session scope, so it belongs here
        // above the platform fork rather than in either shell — a notice about
        // the whole deployment that only macOS could see would be worse than
        // none.
        //
        // Advisory, and advisory on purpose: it blocks nothing. The window is
        // exactly when a client most needs to reach the server, to receive the
        // build the window exists for.
        if let notice = appState.maintenanceNotice {
            HQBanner(kind: .warning, text: notice)
        }

        // Without a registered handle nobody can add you, so this is not a
        // passing error — it stays until it is resolved, and it carries the
        // control that resolves it.
        if let taken = appState.usernameRejected {
            HQBanner(
                kind: .warning,
                text: "@\(taken) is already taken — pick another username",
                actionTitle: "choose",
                action: { appState.showAccountSettings() }
            )
        }
    }
}

// MARK: - Connection banner

/// Maps `AppState.connectionStatus` onto a banner, or nothing when the
/// connection is healthy. Added once, high in the view tree, so both platforms
/// get it — they previously surfaced connection state through entirely
/// different toolbar glyphs and no banner at all.
struct ConnectionBanner: View {
    @ObservedObject var appState: AppState

    var body: some View {
        Group {
            switch appState.connectionStatus {
            case .offline:
                HQBanner(
                    kind: .offline,
                    text: "You're offline. Messages will send when you're back."
                )
            case .connecting where appState.isReconnecting:
                HQBanner(kind: .reconnecting, text: "Reconnecting…")
            case .error(let message):
                HQBanner(
                    kind: .error,
                    text: message.components(separatedBy: "\n\n").first ?? message,
                    actionTitle: "retry",
                    action: {
                        Task { await appState.connectToServer(force: true) }
                    }
                )
            case .disconnected, .connecting, .connected, .authenticated, .notAdmitted:
                EmptyView()
            }
        }
        .animation(.easeInOut(duration: 0.2), value: appState.isReconnecting)
    }
}
