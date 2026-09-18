//
//  ProfileSelectionView.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import SwiftUI
import SwiftData
import LocalAuthentication

struct ProfileSelectionView: View {
    @Environment(\.modelContext) private var modelContext
    @EnvironmentObject var appState: AppState
    /// Injected, never constructed here. This view used to create its own
    /// `ProfileManager` over the same `ModelContext`, so a profile created in
    /// the sheet only ever landed in *that* instance — the rest of the app kept
    /// reading `AppState`'s copy and stayed stale until the app was relaunched.
    @ObservedObject var profileManager: ProfileManager
    /// Set when this screen is presented over the app (the profile switcher).
    /// A full-screen cover has no drag-to-dismiss, so it needs a way out; the
    /// first-run presentation passes nil and shows no close control.
    var onClose: (() -> Void)?
    @State private var showingCreateProfile = false
    @State private var newProfileUsername = ""
    @State private var newProfileServerURL = ""
    @State private var errorMessage: String?

    /// App-wide unsecure "fast unlock" mode (see AuthPrefs); also in Settings.
    @AppStorage(AuthPrefs.unsecureKeyHoldKey) private var unsecureKeyHold = false
    @State private var showingError = false
    @State private var showingResetConfirmation = false

    /// What this device can gate a key behind. Probed on appear AND on every
    /// return to foreground: the remedy for two of the four cases is "go to
    /// Settings and set it up", so the answer changes while this very screen is
    /// on screen. A one-shot probe would leave someone who did exactly what they
    /// were told staring at the same refusal.
    @State private var capability: DeviceAuthCapability = .biometrics
    /// How the profile being created will unlock — nil until the user says.
    ///
    /// Deliberately NOT defaulted. A preselected row is a decision made on
    /// someone's behalf and then reported to them as though they had made it,
    /// which is the wrong shape for the one setting on this screen that cannot
    /// be changed afterwards. `create` stays disabled until this is answered.
    ///
    /// The exception is a device with only one option, where there is no choice
    /// to present: that is filled in, because requiring a tap on the only thing
    /// available is friction with no decision inside it.
    @State private var selectedTier: KeyProtectionTier?
    @Environment(\.scenePhase) private var scenePhase
    
    /// First-run welcome / login hero shown when no profiles exist yet.
    private var welcomeHero: some View {
        VStack(spacing: 22) {
            HQLogoMark(size: 72)

            VStack(spacing: 8) {
                HQWordmark(size: 34)
                Text("private, post-quantum messaging")
                    .font(HQFont.mono(11, weight: .semibold))
                    .tracking(2)
                    .foregroundColor(HQColor.textDim)
            }

            VStack(spacing: 14) {
                welcomeFeature("lock.fill", "end-to-end encrypted", "HQC + AES-256 on every message and call", HQColor.green)
                welcomeFeature("key.fill", "keys stay on your device", "secured by the Secure Enclave & Keychain", HQColor.purpleLight)
                welcomeFeature("person.2.fill", "multiple identities", "separate profiles, each with its own keys", HQColor.green)
            }
            .padding(.horizontal, 8)
            .padding(.top, 4)

            Text("create a profile to get started")
                .font(HQFont.ui(13))
                .foregroundColor(HQColor.textMuted)
                .padding(.top, 4)
        }
        .padding(.top, 40)
        .padding(.horizontal)
    }

    private func welcomeFeature(_ icon: String, _ title: String, _ subtitle: String, _ tint: Color) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundColor(tint)
                .accessibilityHidden(true)
                .frame(width: 38, height: 38)
                .background(tint.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 5))
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(tint.opacity(0.35), lineWidth: 1))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(HQFont.ui(15, weight: .bold)).foregroundColor(HQColor.textPrimary)
                Text(subtitle).font(HQFont.ui(12.5)).foregroundColor(HQColor.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }

    /// Shown only when no profile can be created here at all.
    ///
    /// Deliberately BEFORE the button rather than after the failure. The whole
    /// shape of the reported bug was that the app let someone commit to a handle,
    /// spend a keygen, and only then say -25293 at them.
    ///
    /// Reduced protection is NOT announced here any more — that is a property of
    /// the profile you are about to make, so it belongs in the sheet that makes
    /// it. Saying it in both places turned one decision into two warnings in two
    /// places with two different phrasings.
    @ViewBuilder
    private var protectionNotice: some View {
        if capability.tier == nil {
            VStack(alignment: .leading, spacing: 8) {
                HQFieldLabel(text: "cannot continue", tint: HQColor.danger)
                Text(capability.headline)
                    .font(HQFont.ui(14, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(capability.remedy)
                    .font(HQFont.ui(12.5))
                    .foregroundColor(HQColor.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .hqCard(accent: HQColor.danger)
            .padding(.horizontal)
        }
    }

    @ViewBuilder
    private var actionButtons: some View {
        #if DEBUG
        // Nothing has been created yet, so there is nothing to wipe. A destructive
        // control that cannot destroy anything is noise on the one screen that
        // should read as "start here" — and on first run it sat directly under
        // the primary action, in danger red, as the second thing the eye lands on.
        if !profileManager.profiles.isEmpty {
        Button {
            showingResetConfirmation = true
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "trash")
                Text("reset all")
            }
        }
        .buttonStyle(HQDangerButtonStyle())
        .help("Delete all profiles, keys, and data (dev mode only)")
        }
        #endif
    }

    var body: some View {
        VStack(spacing: 20) {
            if let onClose {
                HStack {
                    Spacer()
                    Button { onClose() } label: {
                        Text("[esc]")
                            .font(HQFont.mono(13, weight: .bold))
                            .foregroundColor(HQColor.textSecond)
                            .padding(.horizontal, 10).padding(.vertical, 6)
                            .overlay(Rectangle().stroke(Color.white.opacity(0.18), lineWidth: 1))
                            .hqTapTarget()
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("close profile switcher")
                }
            }

            if profileManager.profiles.isEmpty {
                welcomeHero
            } else {
                // Header
                VStack(spacing: 8) {
                    HQLogoMark(size: 56)
                        .padding(.bottom, 8)

                    (Text("select ").fontWeight(.light) + Text("profile").fontWeight(.bold))
                        .font(.system(size: 26))
                        .foregroundColor(.white)

                    Text("each identity carries its own keys, friends, and history")
                        .font(HQFont.ui(13.5))
                        .foregroundColor(HQColor.textMuted)
                        .multilineTextAlignment(.center)
                }
                .padding(.top, 40)

                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(profileManager.profiles) { profile in
                            ProfileRow(
                                profile: profile,
                                isActive: profile.id == profileManager.currentProfile?.id,
                                onSelect: {
                                    selectProfile(profile)
                                },
                                onDelete: {
                                    deleteProfile(profile)
                                }
                            )
                        }
                    }
                    .padding(.horizontal)
                }
                .frame(maxHeight: 400)
            }
            
            // Action stack
            VStack(spacing: 9) {
                protectionNotice

                Button {
                    beginProfileCreation()
                } label: {
                    HStack(spacing: 9) {
                        Image(systemName: "plus").font(.system(size: 15, weight: .heavy))
                        Text("new profile")
                    }
                }
                .buttonStyle(HQPrimaryButtonStyle())
                // No key can be stored at all in these states, so there is
                // nothing behind this button but the failure the notice above
                // already explains.
                .disabled(capability.tier == nil)
                .opacity(capability.tier == nil ? 0.45 : 1)

                HStack(spacing: 9) {
                    actionButtons
                }

            }
            .padding(.horizontal)
            .padding(.bottom, 20)
        }
        .padding()
        // Size FIRST, paint second. `.background` sizes its backdrop to the
        // content it is attached to, so expanding the frame afterwards left the
        // gradient painted over the VStack's bounds and the raw window colour
        // above and below it — two hard horizontal edges across the screen.
        // `HQScreenBackground` already ignores the safe area; it could not help
        // while it was being handed a box to fill. `CreateProfileSheet` below has
        // always had these the right way round.
        #if os(macOS)
        .frame(width: 500, height: 640)
        #else
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        #endif
        .hqScreenBackground()
        .sheet(isPresented: $showingCreateProfile) {
            CreateProfileSheet(
                username: $newProfileUsername,
                serverURL: $newProfileServerURL,
                tier: $selectedTier,
                capability: capability,
                onSelectTier: { selectTier($0) },
                onSave: {
                    createProfile()
                },
                onCancel: {
                    newProfileUsername = ""
                    newProfileServerURL = ""
                    selectedTier = nil
                    showingCreateProfile = false
                }
            )
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") {
                errorMessage = nil
                showingError = false
            }
        } message: {
            if let error = errorMessage {
                Text(error)
            } else {
                Text("An unknown error occurred")
            }
        }
        .onAppear { capability = .current }
        .onChange(of: scenePhase) { _, phase in
            // Coming back from Settings, where the fix for two of these states
            // lives.
            if phase == .active { capability = .current }
        }
        .alert("Reset All Data", isPresented: $showingResetConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Reset", role: .destructive) {
                resetAllData()
            }
        } message: {
            Text("This will delete ALL data:\n• All profiles\n• All friends and messages\n• All keys from Keychain\n• All UserDefaults\n\nThis action cannot be undone!")
        }
    }
    
    /// Selecting a profile is one step: Face ID, then straight into the app.
    /// There used to be a second "enter hqchat" button after this, so every
    /// launch cost two taps for a decision the user had already made.
    private func selectProfile(_ profile: Profile) {
        do {
            try profileManager.switchToProfile(profile)
            enter()
        } catch {
            errorMessage = error.localizedDescription
            showingError = true
        }
    }

    /// Hand off to the main app with the now-active profile.
    private func enter() {
        appState.hasActiveProfile = true
        Task { await appState.initialize() }
    }
    
    /// One path to the sheet, whatever the device can do.
    ///
    /// The device sets the starting point — the best protection it can give —
    /// and the sheet is where that is shown and, where there is a choice, changed.
    private func beginProfileCreation() {
        capability = .current
        guard let only = capability.tier else { return }
        // Two options means the user picks; one means there is nothing to pick.
        selectedTier = capability.offersWeakerAlternative ? nil : only
        showingCreateProfile = true
    }

    /// Choosing "Secure" is what asks for Face ID — the choice and the consent
    /// are the same act.
    ///
    /// Asking at `create` instead meant the permission dialog arrived after a
    /// handle had been typed, at the one moment someone is least inclined to say
    /// no to anything. And a refusal there left the form sitting on a protection
    /// the device had just declined to provide. Here a refusal simply leaves the
    /// row unchosen, with the selector re-probed and showing what is actually
    /// available.
    private func selectTier(_ tier: KeyProtectionTier) {
        guard tier == .biometryCurrentSet else {
            selectedTier = tier
            return
        }
        Task {
            if await confirmBiometricConsent() {
                selectedTier = .biometryCurrentSet
            }
        }
    }

    private func createProfile() {
        let username = UsernameRule.normalized(newProfileUsername)
        // The same rule the server enforces, checked before a keypair is even
        // generated — an identity that can't register is worse than no identity.
        if let reason = UsernameRule.rejectionReason(username) {
            errorMessage = "Username: \(reason)."
            showingError = true
            return
        }
        Task { await create(username: username) }
    }

    /// Ask the biometric question BEFORE writing a key only biometrics can open.
    ///
    /// Storing a `.biometryCurrentSet` item raises no prompt — writing does not
    /// authenticate — so the app could mint a tier-2 key, and only later, at the
    /// first read, discover that iOS had never asked for Face ID permission or
    /// that the user had said no. The key was then unreadable and the profile
    /// unopenable, which is `.biometryDenied` arriving after the damage instead
    /// of before it.
    ///
    /// One evaluation settles it: it triggers the system's one-time permission
    /// dialog at the moment the user is choosing this protection, proves the
    /// enrolment actually works for this app, and costs nothing on the quick
    /// unlock path, which does not need it.
    private func confirmBiometricConsent() async -> Bool {
        // Never beside another prompt. iOS cancels one of two, and the cancelled
        // one is ours — the same collision `MessageKeyGate` waits out at launch,
        // which is exactly when this screen is on top.
        _ = await BiometricCoordinator.waitUntilFree(timeout: 15)
        // …and waiting is only half of it: announce ours too, or the message
        // unlock raises one straight into the middle of it. Waiting without
        // announcing is what made this look like "a second Face ID appeared".
        BiometricCoordinator.begin()
        defer { BiometricCoordinator.end() }

        let context = LAContext()
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Confirm it's you, so this profile's keys can be locked to your Face ID")
        } catch {
            // A refusal here is not a failure to report and move past — it
            // changes what this device can do. Re-probe so the sheet offers what
            // is actually available now (a denial lands in `.biometryDenied`),
            // and say which of the two happened.
            let previous = capability
            capability = .current
            if previous != capability {
                errorMessage = "\(capability.headline) \(capability.remedy)"
            } else {
                errorMessage = "Face ID was not confirmed, so no profile was created. Nothing has been changed."
            }
            showingError = true
            return false
        }
    }

    @MainActor
    private func create(username: String) async {
        // The biometric consent already happened, at the moment "Secure" was
        // chosen. Nothing to ask here.
        guard selectedTier != nil else { return }

        do {
            let profile = try profileManager.createProfile(
                username: username,
                serverURL: newProfileServerURL,
                consentedTier: selectedTier
            )

            // Cache the handle — registered with the server once the account is
            // admitted (see AppState.onAuthSuccess).
            profile.desiredUsername = username
            try? modelContext.save()

            try profileManager.switchToProfile(profile, skipBiometricVerification: true)

            newProfileUsername = ""
            newProfileServerURL = ""
            selectedTier = nil
            showingCreateProfile = false
            enter()
        } catch {
            errorMessage = error.localizedDescription
            showingError = true
            // Keep sheet open so user can see error and try again
        }
    }
    
    private func deleteProfile(_ profile: Profile) {
        do {
            try profileManager.deleteProfile(profile)
        } catch {
            errorMessage = error.localizedDescription
            showingError = true
        }
    }
    
    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .none
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: date)
    }
    
    private func resetAllData() {
        let success = DataResetService.resetAllData(modelContext: modelContext, profileManager: profileManager)
        if success {
            // Reload profiles (should be empty now)
            profileManager.loadProfiles()
            profileManager.loadActiveProfile()
            // Reset app state
            appState.hasActiveProfile = false
            errorMessage = nil
        } else {
            errorMessage = "Failed to reset all data. Some items may not have been deleted."
        }
    }
}

struct ProfileRow: View {
    let profile: Profile
    let isActive: Bool
    let onSelect: () -> Void
    let onDelete: () -> Void
    
    @State private var showingDeleteConfirmation = false
    
    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .none
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: date)
    }
    
    var body: some View {
        HStack(spacing: 13) {
            HQAvatar(name: profile.username, size: 46, glow: isActive ? HQColor.green : HQColor.purple)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text("@\(profile.username)")
                        .font(HQFont.ui(16.5, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)

                    if isActive {
                        Image(systemName: "checkmark")
                            .accessibilityHidden(true)
                            .font(.system(size: 9, weight: .heavy))
                            .foregroundColor(HQColor.onGreen)
                            .frame(width: 16, height: 16)
                            .background(HQColor.green)
                            .clipShape(Circle())
                            .shadow(color: HQColor.green.opacity(0.8), radius: 6)
                    }
                }

                Text("created \(formatDate(profile.createdAt))")
                    .font(HQFont.mono(11))
                    .foregroundColor(HQColor.textDim)

                Text("pk \(profile.publicKeyHex.prefix(5))…")
                    .font(HQFont.mono(11))
                    .foregroundColor(HQColor.textFaint)
            }

            Spacer()

            HStack(spacing: 8) {
                if !isActive {
                    Button {
                        onSelect()
                    } label: {
                        Text("select")
                            .font(HQFont.ui(13, weight: .semibold))
                            .foregroundColor(HQColor.green)
                            .padding(.horizontal, 14).padding(.vertical, 7)
                            .background(HQColor.green.opacity(0.08))
                            .overlay(RoundedRectangle(cornerRadius: 3).stroke(HQColor.green.opacity(0.4), lineWidth: 1))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                    .buttonStyle(.plain)
                }

                Button {
                    showingDeleteConfirmation = true
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 14))
                        .foregroundColor(HQColor.danger)
                        .frame(width: 32, height: 32)
                        .background(HQColor.danger.opacity(0.06))
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(HQColor.danger.opacity(0.28), lineWidth: 1))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .hqTapTarget()
                }
                .buttonStyle(.plain)
                .accessibilityLabel("delete profile @\(profile.username)")
            }
        }
        .hqCard(selected: isActive, padding: 14)
        .hqCornerBrackets(HQColor.green, show: isActive)
        .alert("Delete Profile", isPresented: $showingDeleteConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                onDelete()
            }
        } message: {
            Text("Are you sure you want to delete @\(profile.username)? This will also delete all friends and messages for this profile.")
        }
    }
}

struct CreateProfileSheet: View {
    @Binding var username: String
    @Binding var serverURL: String
    /// Which gate this profile's keys will carry. Nil until answered — there is
    /// no default, so nothing is chosen on the user's behalf.
    @Binding var tier: KeyProtectionTier?
    /// What the device can actually do — decides whether there is a choice here
    /// at all, and explains why when there isn't.
    let capability: DeviceAuthCapability
    /// Selection goes through the parent: picking "Secure" has to raise the
    /// biometric consent before it can be honoured, and that is async.
    let onSelectTier: (KeyProtectionTier) -> Void
    let onSave: () -> Void
    let onCancel: () -> Void

    /// Which version of the agreement this human has accepted, app-wide. See
    /// `EulaPrefs` for why it is a version and not a Bool, and for why
    /// `DataResetService` deliberately leaves it alone.
    @AppStorage(EulaPrefs.acceptedVersionKey) private var acceptedEula: String = ""

    /// Only shown once the field has been typed in — an empty new form should
    /// not open with a complaint.
    private var rejection: String? {
        username.isEmpty ? nil : UsernameRule.rejectionReason(username)
    }

    var body: some View {
        VStack(spacing: 0) {
            // Nav bar
            HStack {
                Button("cancel") { onCancel() }
                    .buttonStyle(.plain)
                    .font(HQFont.ui(15))
                    .foregroundColor(HQColor.textSecond)
                Spacer()
                Text("new profile")
                    .font(HQFont.ui(16, weight: .bold))
                    .foregroundColor(.white)
                Spacer()
                Button("create") { onSave() }
                    .buttonStyle(.plain)
                    .font(HQFont.ui(15, weight: .semibold))
                    .foregroundColor(canCreate ? HQColor.green : HQColor.textOff)
                    .disabled(!canCreate)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 16)
            .overlay(Rectangle().fill(HQColor.hairline).frame(height: 1), alignment: .bottom)

            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    // One name, not two. A profile used to ask for a local label
                    // *and* a username, so every identity had a private name
                    // nobody else ever saw and a public one that actually mattered.
                    HQFieldLabel(text: "username").padding(.bottom, 9)
                    HQTextField(placeholder: "handle", text: $username, monospaced: true, prefix: "@")
                        .onChange(of: username) { _, newValue in
                            // Filter as typed, with the same alphabet the server
                            // accepts — nothing else can be typed or pasted in.
                            let clean = UsernameRule.sanitized(newValue)
                            if clean != newValue { username = clean }
                        }
                        .onSubmit { if canCreate { onSave() } }

                    if let rejection {
                        Text(rejection)
                            .font(HQFont.mono(12))
                            .foregroundColor(HQColor.warning)
                            .padding(.top, 9).padding(.horizontal, 2)
                    } else {
                        Text("how friends find and add you · \(UsernameRule.hint)")
                            .font(HQFont.ui(12.5)).foregroundColor(HQColor.textDim)
                            .padding(.top, 9).padding(.horizontal, 2)
                    }

                    HQFieldLabel(text: "home server (optional)").padding(.top, 26).padding(.bottom, 9)
                    HQTextField(placeholder: "wss://… (leave blank for default)", text: $serverURL, monospaced: true)
                    Text("the server this profile connects to. friends must share it.")
                        .font(HQFont.ui(12.5)).foregroundColor(HQColor.textDim)
                        .padding(.top, 9).padding(.horizontal, 2)

                    protectionSection

                    agreementSection

                    // Key generation note
                    HStack(alignment: .top, spacing: 11) {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 14))
                            .foregroundColor(HQColor.purpleLight)
                            .accessibilityHidden(true)
                            .frame(width: 30, height: 30)
                            .background(HQColor.purple.opacity(0.1))
                            .overlay(RoundedRectangle(cornerRadius: 4).stroke(HQColor.purple.opacity(0.35), lineWidth: 1))
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                        VStack(alignment: .leading, spacing: 2) {
                            Text("a fresh keypair is forged on-device")
                                .font(HQFont.ui(13, weight: .semibold))
                                .foregroundColor(HQColor.textOnCard)
                            Text("HQC-256 · keys never leave this phone")
                                .font(HQFont.mono(11.5))
                                .foregroundColor(HQColor.textMuted)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(14)
                    .background(Color.white.opacity(0.02))
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.white.opacity(0.07), lineWidth: 1))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                    .padding(.top, 30)
                }
                .padding(.horizontal, 22)
                .padding(.top, 26)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .hqScreenBackground()
        .sheetSizing(minHeight: 560)
    }

    /// All three answers are required. The handle was always mandatory; the
    /// protection is too, because nothing preselects it; and the agreement is,
    /// because App Store Guideline 1.2 asks a user-generated-content app to
    /// obtain it before the app is used, and this screen is the only moment
    /// before the app is used.
    private var canCreate: Bool {
        UsernameRule.isValid(username) && tier != nil && acceptedEula == EulaPrefs.currentVersion
    }

    /// The agreement, beside the protection tier because it is the same kind of
    /// thing: a required, non-preselected consent, visible while you decide
    /// rather than a dialog dismissed on the way in.
    ///
    /// ⚠️ One case IS preselected, and on purpose: somebody making a SECOND
    /// profile has already agreed, and the value is app-wide because it records
    /// what a person agreed to rather than what an identity did. Asking the same
    /// human twice is theatre. It un-checks itself when `EulaPrefs.currentVersion`
    /// moves, which is the case that should re-ask.
    @ViewBuilder
    private var agreementSection: some View {
        HQFieldLabel(text: "agreement",
                     tint: acceptedEula == EulaPrefs.currentVersion ? HQColor.green : HQColor.textDim)
            .padding(.top, 26).padding(.bottom, 9)

        Button {
            acceptedEula = acceptedEula == EulaPrefs.currentVersion ? "" : EulaPrefs.currentVersion
        } label: {
            HStack(alignment: .top, spacing: 11) {
                Image(systemName: acceptedEula == EulaPrefs.currentVersion
                      ? "checkmark.square.fill" : "square")
                    .font(.system(size: 14))
                    .foregroundColor(acceptedEula == EulaPrefs.currentVersion
                                     ? HQColor.green : HQColor.textDim)
                    .accessibilityHidden(true)
                    .frame(width: 30, height: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text("i agree to the terms")
                        .font(HQFont.ui(13.5, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)
                    Text("no abuse, no harassment, no illegal content. people who do that get removed.")
                        .font(HQFont.ui(11.5))
                        .foregroundColor(HQColor.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
        }
        .buttonStyle(.plain)
        .hqTapTarget()
        .accessibilityLabel("i agree to the terms")
        .accessibilityAddTraits(acceptedEula == EulaPrefs.currentVersion ? [.isSelected] : [])

        Link("read the full agreement", destination: Deployment.eulaURL)
            .font(HQFont.ui(12.5))
            .foregroundColor(HQColor.purpleLight)
            .padding(.top, 9).padding(.horizontal, 2)
    }

    /// What unlocks this profile's keys, decided here rather than in an alert
    /// somewhere behind this screen.
    ///
    /// Beside the handle and the server because it is the same kind of fact: a
    /// property of the identity being made, fixed at creation, and worth seeing
    /// while you make it. The warning for the weaker option stays on screen the
    /// whole time you are typing rather than being a dialog dismissed on the way
    /// in — which is a stronger form of consent, not a weaker one.
    @ViewBuilder
    private var protectionSection: some View {
        HQFieldLabel(text: "protection",
                     tint: tier == nil ? HQColor.textDim
                         : (tier?.isReduced == true ? HQColor.warning : HQColor.green))
            .padding(.top, 26).padding(.bottom, 9)

        if capability.offersWeakerAlternative {
            VStack(spacing: 9) {
                protectionOption(.biometryCurrentSet,
                                 icon: "faceid",
                                 title: "Secure",
                                 subtitle: "Face ID every time your keys are used")
                protectionOption(.userPresence,
                                 icon: "bolt.fill",
                                 title: "Quick unlock",
                                 subtitle: "weaker · one unlock per launch, then never again")
            }
        } else {
            // One option is not a choice, and a picker with a single row implies
            // a decision nobody got to make. Show what it will be, and why.
            protectionOption(.userPresence,
                             icon: "bolt.fill",
                             title: "Quick unlock",
                             subtitle: capability.headline,
                             selectable: false)
        }

        Text(protectionFootnote)
            .font(HQFont.ui(12.5))
            .foregroundColor(tier?.isReduced == true ? HQColor.warning : HQColor.textDim)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 9).padding(.horizontal, 2)
    }

    private var protectionFootnote: String {
        switch tier {
        case .none:
            return "Choose how this profile unlocks. It is fixed when the profile is created and cannot be changed later."
        case .userPresence:
            return "One unlock — Face ID or your passcode, whichever this device has — then the key stays in memory until the app closes. Anyone who can unlock this device can open this identity and read its messages. Fixed when the profile is created; it cannot be changed later."
        case .biometryCurrentSet:
            return "Fixed when the profile is created — it cannot be changed later."
        }
    }

    private func protectionOption(_ option: KeyProtectionTier,
                                  icon: String,
                                  title: String,
                                  subtitle: String,
                                  selectable: Bool = true) -> some View {
        let isOn = tier == option
        let tint = option.isReduced ? HQColor.warning : HQColor.green
        return Button {
            onSelectTier(option)
        } label: {
            HStack(spacing: 11) {
                Image(systemName: icon)
                    .font(.system(size: 14))
                    .foregroundColor(tint)
                    .accessibilityHidden(true)
                    .frame(width: 30, height: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(HQFont.ui(13.5, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)
                    Text(subtitle)
                        .font(HQFont.ui(11.5))
                        .foregroundColor(HQColor.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
                if selectable {
                    Image(systemName: isOn ? "checkmark.circle.fill" : "circle")
                        .font(.system(size: 17))
                        .foregroundColor(isOn ? tint : HQColor.textOff)
                        .accessibilityHidden(true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            // Selected-and-green is the app's "this is fine" state, and the
            // weaker option is not that. It selects in amber, the same colour as
            // its warning, so the choice never looks endorsed.
            .hqCard(selected: isOn && selectable && !option.isReduced,
                    cornerRadius: 4, padding: 12,
                    accent: isOn && option.isReduced ? HQColor.warning : nil)
        }
        .buttonStyle(.plain)
        // `allowsHitTesting`, not `disabled`: the informational row is the ONLY
        // place a passcode-only device is told what it is getting and why, and
        // `disabled` dims that text on exactly the device where it matters most.
        // Inert, not greyed out.
        .allowsHitTesting(selectable)
        .accessibilityAddTraits(isOn ? [.isSelected] : [])
        .accessibilityLabel("\(title). \(subtitle)")
    }
}


