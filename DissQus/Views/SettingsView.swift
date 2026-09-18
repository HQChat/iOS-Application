//
//  SettingsView.swift
//  DissQus
//
//  Settings root. Two pushed screens sit under it: Account (identity + the
//  destructive actions) and Security (the technical detail).
//
//  This used to be one flat system `Form` that put key-management jargon —
//  four read-only encryption rows and a "fast unlock" toggle — on the top-level
//  screen, above the things people actually come here to change.
//

import SwiftUI
import SwiftData

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @Environment(\.modelContext) private var modelContext

    @ObservedObject var userService: UserService
    let profileManager: ProfileManager?
    /// True when hosted in the iOS tab bar, where a "Done" button would make no
    /// sense. macOS still presents this as a sheet.
    var isEmbedded = false

    /// Value-based navigation, so something outside this screen can push into
    /// it — the "username taken" banner sends people straight to Account.
    @State private var path = NavigationPath()

    private enum Route: Hashable { case account, security, diagnostics }

    private var appVersion: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(v) (\(b))"
    }

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                #if os(iOS)
                HQScreenHeader(path: "settings", appState: appState, profileManager: profileManager)
                #endif

                ScrollView {
                VStack(spacing: 22) {
                    profileHeader

                    VStack(spacing: 10) {
                        NavigationLink(value: Route.account) {
                            // Lowercase, like every other piece of chrome this
                            // app draws itself. Sentence case is reserved for
                            // system surfaces (alerts, share sheets), per HIG.
                            settingsRow(icon: "person.crop.circle",
                                        title: "account",
                                        subtitle: "username, keys, delete account",
                                        tint: HQColor.green)
                        }
                        .buttonStyle(.plain)

                        NavigationLink(value: Route.security) {
                            settingsRow(icon: "lock.shield",
                                        title: "security",
                                        subtitle: "unlock behaviour and what's encrypted",
                                        tint: HQColor.purpleLight)
                        }
                        .buttonStyle(.plain)

                        NavigationLink(value: Route.diagnostics) {
                            settingsRow(icon: "waveform.path.ecg",
                                        title: "diagnostics",
                                        subtitle: "key exchange, greetings, and what got dropped",
                                        tint: HQColor.warning)
                        }
                        .buttonStyle(.plain)

                        // The app linked to NEITHER of these before, which is
                        // both an App Store requirement (Guideline 1.2 wants the
                        // terms reachable and a contact point that answers) and
                        // an ordinary gap: the pages have existed for a while
                        // and nothing in the app pointed at them.
                        //
                        // `Link`, not a NavigationLink: these are the published
                        // pages, and a reviewer checking them should land on the
                        // same URL App Store Connect was given rather than on a
                        // copy that can drift from it.
                        Link(destination: Deployment.eulaURL) {
                            settingsRow(icon: "doc.text",
                                        title: "terms",
                                        subtitle: "what you agreed to · what gets you removed",
                                        tint: HQColor.textSecond)
                        }
                        .buttonStyle(.plain)

                        Link(destination: Deployment.privacyURL) {
                            settingsRow(icon: "hand.raised",
                                        title: "privacy",
                                        subtitle: "what this server holds, and what it cannot",
                                        tint: HQColor.textSecond)
                        }
                        .buttonStyle(.plain)

                        Link(destination: Deployment.supportURL) {
                            settingsRow(icon: "envelope",
                                        title: "support",
                                        subtitle: "report abuse, or ask a human",
                                        tint: HQColor.textSecond)
                        }
                        .buttonStyle(.plain)
                    }

                    privacyStanceCard

                    Text("hqchat \(appVersion)")
                        .font(HQFont.mono(11))
                        .foregroundColor(HQColor.textFaint)
                        .padding(.top, 4)
                }
                .padding()
                }
            }
            .background(HQScreenBackground())
            #if os(iOS)
            // The prompt header names the screen (see HQPromptHeader).
            .toolbar(.hidden, for: .navigationBar)
            #else
            .navigationTitle("Settings")
            #endif
            .navigationDestination(for: Route.self) { route in
                switch route {
                case .account:
                    AccountSettingsView(userService: userService,
                                        profileManager: profileManager)
                case .security:
                    SecuritySettingsView()
                case .diagnostics:
                    ProtocolLogView()
                }
            }
            .toolbar {
                if !isEmbedded {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { dismiss() }
                    }
                }
            }
        }
        // Someone else asked for Account — a banner, usually.
        //
        // Both hooks are needed. On iOS this view is already alive in the tab
        // bar when the flag flips, so `onChange` sees it. On macOS the same
        // banner OPENS this view as a sheet, and the flag was set before the
        // sheet existed — a change nothing was watching. `onAppear` catches it.
        .onAppear { consumeAccountRequest() }
        .onChange(of: appState.openAccountSettings) { _, wanted in
            guard wanted else { return }
            consumeAccountRequest()
        }
    }

    /// Push Account if something asked for it, and clear the request so it is
    /// honoured once rather than on every appearance.
    private func consumeAccountRequest() {
        guard appState.openAccountSettings else { return }
        if !path.isEmpty { path = NavigationPath() }
        path.append(Route.account)
        appState.openAccountSettings = false
    }

    /// The handle in force right now: the server's answer if we have it, else
    /// the one this profile was created with. A handle the server *refused*
    /// counts as neither — showing it here would claim an identity this device
    /// does not own.
    private var handle: String? {
        if let confirmed = userService.currentUsername { return confirmed }
        if appState.usernameRejected != nil { return nil }
        return profileManager?.currentProfile?.username
    }

    /// Who you currently are, and a one-tap way to be someone else. Switching
    /// profiles used to be buried in the "…" toolbar menu.
    private var profileHeader: some View {
        VStack(spacing: 12) {
            HQAvatar(name: handle ?? "?", size: 64, glow: HQColor.purple)

            VStack(spacing: 3) {
                // One name. This card used to stack a local profile label on top
                // of the username, which read as two different identities.
                Text(handle.map { "@\($0)" } ?? "no profile")
                    .font(HQFont.ui(18, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)

                // Labelled, because eight hex characters on their own read as
                // an error code rather than as this identity's fingerprint.
                if let key = profileManager?.currentProfile?.publicKey {
                    Text("key \(HQFingerprint.short(key))")
                        .font(HQFont.mono(12))
                        .foregroundColor(HQColor.textMuted)
                        .accessibilityLabel("key fingerprint \(HQFingerprint.short(key))")
                }
            }

            #if os(iOS)
            Button("switch profile") {
                appState.showingProfileSwitcher = true
            }
            .buttonStyle(HQSecondaryButtonStyle())
            .frame(maxWidth: 220)
            #endif
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
        .hqCard(accent: HQColor.purple)
    }

    /// What this app deliberately does *not* do. Read receipts and typing
    /// indicators are a product decision here, not an unfinished feature — but
    /// an absence that isn't stated reads as a gap, so it is stated.
    private var privacyStanceCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HQFieldLabel(text: "what we don't send", tint: HQColor.textMuted)
            ForEach(["no read receipts — nobody is told when you open a message",
                     "no typing indicators",
                     "no last-seen; presence is only shown to your contacts, only while you're connected"],
                    id: \.self) { line in
                HStack(alignment: .top, spacing: 8) {
                    Text("·")
                        .font(HQFont.mono(12, weight: .bold))
                        .foregroundColor(HQColor.textDim)
                    Text(line)
                        .font(HQFont.ui(12.5))
                        .foregroundColor(HQColor.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .hqCard()
    }

    private func settingsRow(icon: String, title: String, subtitle: String, tint: Color) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 17))
                .foregroundColor(tint)
                .accessibilityHidden(true)
                .frame(width: 34, height: 34)
                .background(tint.opacity(0.08))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(tint.opacity(0.30), lineWidth: 1))
                .clipShape(RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(HQFont.ui(15.5, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)
                Text(subtitle)
                    .font(HQFont.ui(12))
                    .foregroundColor(HQColor.textMuted)
            }

            Spacer()

            Image(systemName: "chevron.right")
                .accessibilityHidden(true)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(HQColor.textFaint)
        }
        .padding(14)
        .hqCard(accent: tint)
    }
}
