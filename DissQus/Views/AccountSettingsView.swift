//
//  AccountSettingsView.swift
//  DissQus
//
//  Identity, and the two irreversible actions — kept together but visually
//  separated, so "delete my account" is never adjacent to a routine control.
//

import SwiftUI
import SwiftData

struct AccountSettingsView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @Environment(\.modelContext) private var modelContext

    @ObservedObject var userService: UserService
    let profileManager: ProfileManager?

    @State private var isEditingUsername = false
    @State private var draftUsername = ""
    @State private var appError: AppError?
    @State private var showingResetConfirm = false
    @State private var showingDeleteAccountConfirm = false
    @State private var isDeletingAccount = false

    private var fingerprint: String? {
        guard let key = profileManager?.currentProfile?.publicKey else { return nil }
        return HQFingerprint.short(key)
    }

    /// Nothing to save when the name hasn't actually changed. Without this the
    /// Save button fired a full `set_username` round-trip for an identical
    /// value, which the server then had to special-case as a no-op. The rule
    /// check is the same one the server applies, so an impossible handle is
    /// refused here rather than after a round-trip.
    private var canSaveUsername: Bool {
        let trimmed = UsernameRule.normalized(draftUsername)
        return UsernameRule.isValid(trimmed) && trimmed != (userService.currentUsername ?? "")
    }

    /// Why the draft can't be saved, once something has been typed.
    private var usernameRejection: String? {
        draftUsername.isEmpty ? nil : UsernameRule.rejectionReason(draftUsername)
    }

    var body: some View {
        VStack(spacing: 0) {
            #if os(iOS)
            HQSubScreenHeader(path: "settings/account") { dismiss() }
            #endif
            ScrollView {
                VStack(spacing: 22) {
                    usernameCard
                    identityCard
                    dangerZone
                }
                .padding()
            }
        }
        .background(HQScreenBackground())
        #if os(iOS)
        .toolbar(.hidden, for: .navigationBar)
        .hqSwipeNavigation(onBack: { dismiss() })
        #else
        .navigationTitle("Account")
        .inlineNavTitle()
        #endif
        .hqError($appError)
        // `alert`, not `confirmationDialog`: on iOS 26 the dialog's cancel action
        // never reaches the view hierarchy, so the only way out of an
        // irreversible prompt was tapping the dimmed area behind it. An alert
        // renders both buttons, and backing out stays a deliberate choice.
        .alert("Reset all data?", isPresented: $showingResetConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Reset everything", role: .destructive) {
                _ = DataResetService.resetAllData(modelContext: modelContext, profileManager: profileManager)
                appState.hasActiveProfile = false
                dismiss()
            }
        } message: {
            Text("This permanently deletes all profiles, keys, contacts, and messages on this device. Your account on the server is left untouched.")
        }
        .alert("Delete your account?", isPresented: $showingDeleteAccountConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Delete account", role: .destructive) {
                isDeletingAccount = true
                Task {
                    await appState.deleteAccount()
                    isDeletingAccount = false
                    dismiss()
                }
            }
        } message: {
            Text("This permanently deletes your account from the server — username, contacts, push token, and any queued messages — and erases everything on this device. This cannot be undone.")
        }
    }

    // MARK: - Cards

    private var usernameCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HQFieldLabel(text: "username", tint: HQColor.green)

            if isEditingUsername {
                HQTextField(placeholder: "username", text: $draftUsername, prefix: "@")
                    .onChange(of: draftUsername) { _, newValue in
                        // Same alphabet as the server, filtered as typed: the
                        // field can't hold a handle the server would reject, and
                        // nothing crafted can be pasted through it.
                        let clean = UsernameRule.sanitized(newValue)
                        if clean != newValue { draftUsername = clean }
                    }

                Text(usernameRejection ?? UsernameRule.hint)
                    .font(HQFont.mono(12))
                    .foregroundColor(usernameRejection == nil ? HQColor.textDim : HQColor.warning)

                HStack(spacing: 10) {
                    Button("cancel") {
                        isEditingUsername = false
                    }
                    .buttonStyle(HQSecondaryButtonStyle())

                    Button("save") { saveUsername() }
                        .buttonStyle(HQPrimaryButtonStyle(height: 44))
                        .disabled(!canSaveUsername)
                }
            } else {
                HStack {
                    Text(userService.currentUsername.map { "@\($0)" } ?? "not set yet")
                        .font(HQFont.ui(16, weight: .semibold))
                        .foregroundColor(userService.currentUsername == nil
                                         ? HQColor.textMuted : HQColor.textPrimary)
                    Spacer()
                    Button("[change]") {
                        draftUsername = userService.currentUsername ?? ""
                        isEditingUsername = true
                    }
                    .buttonStyle(HQInlineActionStyle())
                }

                Text("This is how people find and add you.")
                    .font(HQFont.ui(12))
                    .foregroundColor(HQColor.textMuted)
            }
        }
        .padding(16)
        .hqCard(accent: HQColor.green)
    }

    private var identityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HQFieldLabel(text: "this device", tint: HQColor.purpleLight)

            if let fingerprint {
                VStack(alignment: .leading, spacing: 4) {
                    Text("key fingerprint")
                        .font(HQFont.ui(13))
                        .foregroundColor(HQColor.textSecond)
                    Text(fingerprint)
                        .font(HQFont.mono(13, weight: .medium))
                        .foregroundColor(HQColor.green)
                        .textSelection(.enabled)
                }
            }
        }
        .padding(16)
        .hqCard(accent: HQColor.purpleLight)
    }

    private var dangerZone: some View {
        VStack(alignment: .leading, spacing: 14) {
            HQFieldLabel(text: "irreversible", tint: HQColor.danger)

            VStack(alignment: .leading, spacing: 8) {
                Button("reset all data on this device") { showingResetConfirm = true }
                    .buttonStyle(HQDangerButtonStyle())
                Text("Deletes every profile, key, contact, and message stored here. Your server account survives.")
                    .font(HQFont.ui(11.5))
                    .foregroundColor(HQColor.textMuted)
            }

            VStack(alignment: .leading, spacing: 8) {
                Button {
                    showingDeleteAccountConfirm = true
                } label: {
                    HStack {
                        Text("delete my account")
                        if isDeletingAccount {
                            Spacer()
                            ProgressView().controlSize(.small)
                        }
                    }
                }
                .buttonStyle(HQDangerButtonStyle())
                .disabled(isDeletingAccount)

                Text("Removes your account from the server as well as this device.")
                    .font(HQFont.ui(11.5))
                    .foregroundColor(HQColor.textMuted)
            }
        }
        .hqCard(padding: 16, accent: HQColor.danger)
    }

    // MARK: - Actions

    private func saveUsername() {
        let name = UsernameRule.normalized(draftUsername)
        guard canSaveUsername else { return }
        Task {
            do {
                try await userService.setUsername(name)
                isEditingUsername = false
                // This screen is where a refused handle gets fixed, so a handle
                // that lands here clears the banner that sent the user over.
                appState.usernameRejected = nil
                if let profile = profileManager?.currentProfile {
                    profile.desiredUsername = nil
                    profile.username = name
                    try? modelContext.save()
                }
            } catch {
                // Server rejections (USERNAME_TAKEN, length, reserved handles)
                // used to be swallowed entirely — the row just kept showing the
                // old value with no explanation.
                appError = .from(error)
                if AppState.isUsernameTaken(error) { appState.usernameRejected = name }
            }
        }
    }
}

/// A label/value pair in the settings idiom.
private struct LabeledRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(HQFont.ui(13))
                .foregroundColor(HQColor.textSecond)
            Spacer()
            Text(value)
                .font(HQFont.ui(14, weight: .medium))
                .foregroundColor(HQColor.textPrimary)
        }
    }
}
