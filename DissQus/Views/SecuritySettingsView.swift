//
//  SecuritySettingsView.swift
//  DissQus
//
//  The technical detail, moved off the settings root: what's actually
//  protected, and the one control that trades security for convenience.
//

import SwiftUI

struct SecuritySettingsView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    /// App-wide unsecure mode: hold the identity key in memory to cut biometric
    /// prompts from three per launch to one. Off by default.
    @AppStorage(AuthPrefs.unsecureKeyHoldKey) private var unsecureKeyHold = false

    /// Which gate the ACTIVE profile's keys actually carry.
    ///
    /// This row is the answer to the complaint that closed APP-2 and e22ecd7:
    /// which protection you ended up with depended on the device, and nothing
    /// recorded it — so no one, the code included, could say what was holding
    /// their key. A tier that can be chosen has to be a tier that can be read
    /// back, or it is just a quieter ladder.
    private var tier: KeyProtectionTier {
        guard let id = appState.profileManager?.currentProfile?.id else {
            return .biometryCurrentSet
        }
        return KeyProtectionTier.stored(for: id.uuidString)
    }

    var body: some View {
        VStack(spacing: 0) {
            #if os(iOS)
            HQSubScreenHeader(path: "settings/security") { dismiss() }
            #endif
            ScrollView {
                VStack(spacing: 22) {
                    fastUnlockCard
                    protectionCard
                }
                .padding()
            }
        }
        .background(HQScreenBackground())
        #if os(iOS)
        .toolbar(.hidden, for: .navigationBar)
        .hqSwipeNavigation(onBack: { dismiss() })
        #else
        .navigationTitle("Security")
        .inlineNavTitle()
        #endif
    }

    private var fastUnlockCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HQFieldLabel(text: "unlocking", tint: HQColor.warning)

            Toggle(isOn: $unsecureKeyHold) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Fast unlock")
                        .font(HQFont.ui(15, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)
                    Text("less secure")
                        .font(HQFont.mono(11, weight: .semibold))
                        .foregroundColor(HQColor.warning)
                }
            }
            .tint(HQColor.green)
            .disabled(tier.holdsKeyForSession)
            .onChange(of: unsecureKeyHold) { _, isOn in
                // Turning it off must immediately drop any held key.
                if !isOn { appState.clearCachedKey() }
            }

            // A toggle that changes nothing is worse than no toggle: this
            // profile already holds its key for the session because that is what
            // its tier IS, and leaving the switch live would let someone turn it
            // "off" and believe they had tightened something.
            Text(tier.holdsKeyForSession
                 ? "Always on for this profile — quick unlock is what it was created with. One authentication covers the whole session; asking again would add friction without adding protection."
                 : "Asks for biometric confirmation once per launch instead of on every secure action. Your identity key is then held in memory while the app is open, and cleared when it goes to the background.")
                .font(HQFont.ui(12))
                .foregroundColor(HQColor.textMuted)
        }
        .padding(16)
        .hqCard(accent: HQColor.warning)
    }

    private var protectionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HQFieldLabel(text: "what's protected", tint: HQColor.green)

            protectionRow(icon: "key.fill",
                          title: "Identity key",
                          detail: unsecureKeyHold
                            ? "Held in memory while open (fast unlock on)"
                            : tier.detail,
                          ok: !unsecureKeyHold && !tier.isReduced)
            if tier.isReduced {
                protectionRow(icon: "exclamationmark.triangle.fill",
                              title: "Reduced protection",
                              detail: "This profile uses quick unlock: one authentication per launch, then its key is held in memory. Anyone who can unlock this device can open the identity and read its messages, and it is not bound to the current Face ID enrolment. Fixed at creation — enrolling Face ID now does not upgrade this profile, only a new one.",
                              ok: false)
            }
            protectionRow(icon: "key.horizontal.fill",
                          title: "Message keys",
                          detail: "Keychain — never in the database",
                          ok: true)
            protectionRow(icon: "lock.fill",
                          title: "Messages in transit",
                          detail: "HQC + AES-256-GCM, end-to-end",
                          ok: true)
            protectionRow(icon: "externaldrive.fill",
                          title: "Messages at rest",
                          detail: "Sealed with a per-profile key that never leaves the Keychain",
                          ok: true)
        }
        .padding(16)
        .hqCard(accent: HQColor.green)
    }

    private func protectionRow(icon: String, title: String, detail: String, ok: Bool) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 15))
                .foregroundColor(ok ? HQColor.green : HQColor.warning)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(HQFont.ui(14.5, weight: .medium))
                    .foregroundColor(HQColor.textPrimary)
                Text(detail)
                    .font(HQFont.ui(11.5))
                    .foregroundColor(HQColor.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 14))
                .foregroundColor(ok ? HQColor.green : HQColor.warning)
        }
    }
}
