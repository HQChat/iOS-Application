//
//  ProfileManager.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation
import SwiftData
import Security
import LocalAuthentication

/// App-wide (NOT per-profile) authentication preferences, persisted in
/// UserDefaults so both the SwiftUI toggles and the non-UI ProfileManager read
/// the same source of truth.
enum AuthPrefs {
    /// When ON, the decrypted identity key is held in memory for the foreground
    /// session so the connection handshake and later key ops don't re-prompt
    /// Face ID on every read — one prompt instead of three+. This is the
    /// explicit "unsecure" trade: the key sits in process memory while the app
    /// runs (cleared on background / profile switch). OFF by default: every key
    /// read goes through a fresh biometric prompt (most secure).
    static let unsecureKeyHoldKey = "unsecureKeyHoldEnabled"
    static var unsecureKeyHold: Bool {
        UserDefaults.standard.bool(forKey: unsecureKeyHoldKey)
    }
}

/// Whether this human has accepted the end-user licence agreement, and which
/// version of it.
///
/// App Store Guideline 1.2 requires a UGC app to obtain agreement to terms that
/// forbid objectionable content and abusive users, before the app is used. There
/// is no `hasOnboarded` flag in this app — onboarding is DERIVED from whether a
/// profile exists (`AppState.hasActiveProfile`) — so the gate lives where the
/// profile is made, beside the protection tier, which is already a mandatory,
/// non-preselected, consented choice on that same screen.
///
/// A VERSION, not a Bool, for the reason `StoreMigration` stores one: a changed
/// agreement has to be able to re-prompt, and a Bool cannot express that.
/// App-wide rather than per-profile, because it records what a PERSON agreed to
/// and one person may hold several identities.
///
/// ⚠️ Deliberately NOT in `DataResetService.clearAllUserDefaults`'s allowlist.
/// That list is four keys long and is an allowlist rather than a domain wipe, so
/// this survives "reset all data" — which is the right answer: a device wipe
/// should not re-ask the same human to agree to the same terms they already
/// agreed to. The comment beside that list says so, so the omission reads as a
/// decision rather than an oversight.
enum EulaPrefs {
    /// Bump when the agreement changes materially. The value is the date the
    /// text on /eula was last revised, which is the same string that page shows —
    /// so "which version did they accept" is answerable without a changelog.
    static let currentVersion = "2026-09-13"
    static let acceptedVersionKey = "eula.acceptedVersion"

    /// The non-UI accessor, so ProfileManager and any later gate read the same
    /// source of truth as the `@AppStorage` binding in the create-profile sheet.
    static var acceptedVersion: String {
        UserDefaults.standard.string(forKey: acceptedVersionKey) ?? ""
    }
    static var isAccepted: Bool { acceptedVersion == currentVersion }
}

/// Manages user profiles: creation, switching, and identity storage
@MainActor
class ProfileManager: ObservableObject {
    @Published var currentProfile: Profile?
    @Published var profiles: [Profile] = []

    let modelContext: ModelContext
    private static let keychainServicePrefix = "com.dissqus.profile"

    /// How many gated Keychain reads this process has made — i.e. how many
    /// biometric prompts the user has been shown. Diagnostics only.
    private static var promptCount = 0

    /// In-memory hold of the current profile's decrypted secret key. Populated
    /// only when `AuthPrefs.unsecureKeyHold` is ON (the app-wide unsecure mode).
    /// Cleared on background, profile switch, and when the mode is turned off.
    private var cachedSecretKey: Data?

    /// The gate the active profile's keys carry. Settled with the profile.
    private(set) var activeTier: KeyProtectionTier = .biometryCurrentSet

    init(modelContext: ModelContext) {
        self.modelContext = modelContext
        // Wipe the legacy plaintext seed from UserDefaults (now Keychain-only).
        UserDefaults.standard.removeObject(forKey: "com.dissqus.seed")
        loadProfiles()
        loadActiveProfile()
    }

    /// Load all profiles from database
    func loadProfiles() {
        let descriptor = FetchDescriptor<Profile>(sortBy: [SortDescriptor(\.createdAt, order: .reverse)])
        profiles = (try? modelContext.fetch(descriptor)) ?? []
        purgeStoredSeeds()
    }

    /// The recovery seed deterministically regenerates the private key, so it is
    /// as sensitive as the key itself but was stored at weaker protection. We no
    /// longer persist it anywhere. Purge any lingering copies on launch: delete
    /// the Keychain seed item and clear the SwiftData `seedHex` for every profile.
    private func purgeStoredSeeds() {
        var changed = false
        for profile in profiles {
            deleteSeed(profileId: profile.id.uuidString)
            if !profile.seedHex.isEmpty {
                profile.seedHex = ""
                changed = true
            }
        }
        if changed { try? modelContext.save() }
    }

    // MARK: - Seed cleanup (device no longer stores seeds)

    private func seedKeychainService(_ profileId: String) -> String {
        "\(Self.keychainServicePrefix).seed.\(profileId)"
    }

    private func deleteSeed(profileId: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: seedKeychainService(profileId),
        ] as CFDictionary)
    }
    
    /// Load the active profile
    func loadActiveProfile() {
        let descriptor = FetchDescriptor<Profile>(
            predicate: #Predicate { $0.isActive == true }
        )
        currentProfile = try? modelContext.fetch(descriptor).first
        // The message-key store has to know whose key its unlock must satisfy —
        // the two keys of one profile share a tier, and the policy it
        // authenticates with follows from that. Set here rather than at each
        // switch site so there is one place where "the active profile" is
        // settled and one place that can go stale.
        MessageKeyStore.setActiveProfile(currentProfile?.id)
        // Read once here rather than on every key read. It is a Keychain lookup
        // with no ACL and no prompt, but `getSecretKey` is on the hot path for
        // every frame that touches the private key.
        activeTier = currentProfile.map { KeyProtectionTier.stored(for: $0.id.uuidString) }
            ?? .biometryCurrentSet
    }

    /// Whether one unlock covers this profile for the whole foreground session.
    ///
    /// Two ways in, and they mean different things. `unsecureKeyHold` is an
    /// app-wide preference someone turned on to cut prompts on a strong key.
    /// Tier 1 is a property of the key itself: it is the unsafe-but-convenient
    /// mode, chosen at creation, and prompting per read on it would buy nothing —
    /// the passcode that opens it once opens it every time.
    private var holdsKeyForSession: Bool {
        AuthPrefs.unsecureKeyHold || activeTier.holdsKeyForSession
    }
    
    /// Create a new profile, optionally attached to a specific home server.
    /// Creates an identity for `username`. There is no separate profile name —
    /// the handle is the identity.
    /// - Parameter consentedTier: the tier the caller has already obtained the
    ///   user's explicit agreement to. Required to create at the reduced tier;
    ///   ignored otherwise. A new call site that forgets it cannot acquire the
    ///   weak gate by omission — it gets a thrown error instead.
    func createProfile(username: String, serverURL: String? = nil,
                       consentedTier: KeyProtectionTier? = nil) throws -> Profile {
        print("[ProfileManager] Creating profile: @\(username)")

        // PREFLIGHT, before a single byte of key material exists.
        //
        // This is the whole bug. The Keychain refuses to create an item whose
        // access control nothing on the device can satisfy, and it says so with
        // `errSecAuthFailed` — so the old order of operations spent a CSPRNG
        // draw and a full HQC keygen, inserted a Profile into the model context,
        // and only then discovered the device could never hold the result. The
        // user saw "-25293" after committing to a handle.
        let capability = DeviceAuthCapability.current
        guard let best = capability.tier else {
            print("[ProfileManager] ❌ device cannot protect a key: \(capability)")
            throw ProfileError.deviceCannotProtectKey(capability)
        }

        // The device sets a CEILING; the user picks at or below it. Those were
        // the same number until someone asked the obvious question — "what if I
        // don't want to use Face ID even though my phone can?" — and the answer
        // was that there was no way to say so, because capability was standing
        // in for preference.
        let tier = consentedTier ?? best
        guard tier.rawValue <= best.rawValue else {
            // Asking for a gate this device cannot deliver. Never silently
            // downgraded into what it CAN do: that is the ladder, and a caller
            // that believes it got tier 2 must not be handed tier 1 quietly.
            print("[ProfileManager] ❌ tier \(tier.rawValue) unavailable on this device")
            throw ProfileError.tierUnavailable(capability)
        }
        // Unchanged and non-negotiable: the weak tier is only ever reached by a
        // caller that asked for it by name, whatever the device can do.
        guard !tier.isReduced || consentedTier == tier else {
            print("[ProfileManager] ❌ reduced tier requested without consent")
            throw ProfileError.downgradeNotConsented(capability)
        }
        
        // Generate new identity
        var seed = Data(count: HQCService.SEED_BYTES)
        let status = seed.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, HQCService.SEED_BYTES, bytes.baseAddress!)
        }
        
        guard status == errSecSuccess else {
            print("[ProfileManager] ❌ Failed to generate random seed: \(status)")
            throw ProfileError.randomGenerationFailed
        }
        print("[ProfileManager] ✅ Generated random seed")
        
        // Generate keypair
        print("[ProfileManager] Generating keypair...")
        let (publicKey, secretKey) = try HQCService.generateKeypair(seed: seed)
        let publicKeyHex = publicKey.hexString
        print("[ProfileManager] ✅ Keypair generated")

        // Create profile. The seed is NOT persisted anywhere — it stays a
        // transient local used only for keypair generation above, then discarded.
        let trimmedURL = serverURL?.trimmingCharacters(in: .whitespacesAndNewlines)
        let profile = Profile(username: username, publicKeyHex: publicKeyHex, seedHex: "",
                              serverURL: (trimmedURL?.isEmpty == false) ? trimmedURL : nil)
        modelContext.insert(profile)
        print("[ProfileManager] ✅ Profile object created with ID: \(profile.id.uuidString)")
        
        // Store secret key in Keychain with profile ID
        print("[ProfileManager] Storing secret key in Keychain...")
        do {
            try storeSecretKey(secretKey, profileId: profile.id.uuidString, tier: tier)
            print("[ProfileManager] ✅ Secret key stored in Keychain")
        } catch {
            print("[ProfileManager] ❌ Failed to store secret key: \(error)")
            // Remove the profile from context if keychain storage fails
            modelContext.delete(profile)
            throw error
        }
        
        // Save
        print("[ProfileManager] Saving to database...")
        do {
            try modelContext.save()
            print("[ProfileManager] ✅ Profile saved to database")
        } catch {
            print("[ProfileManager] ❌ Failed to save profile: \(error)")
            // Try to clean up keychain item
            deleteSecretKey(profileId: profile.id.uuidString)
            throw error
        }
        
        // Load updated list
        loadProfiles()
        print("[ProfileManager] ✅ Profile creation complete. Total profiles: \(profiles.count)")
        
        return profile
    }
    
    /// Switch to a different profile
    /// - Parameter skipBiometricVerification: If true, skip biometric verification (useful when profile was just created)
    func switchToProfile(_ profile: Profile, skipBiometricVerification: Bool = false) throws {
        // Re-selecting the profile that is already active is a no-op. Without
        // this the "switch" tore down and rebuilt identical state, dropped the
        // held key, and re-prompted Face ID for a change that never happened.
        if profile.id == currentProfile?.id && profile.isActive {
            return
        }

        // The held key (if any) belongs to the previous profile — drop it.
        cachedSecretKey = nil
        // Same for the cached message-store keys: one profile's key must never
        // be sitting in memory while another profile's rows are being read.
        MessageKeyStore.clearCache()
        MessageKeyGate.shared.lock()

        // Deactivate all profiles
        for p in profiles {
            p.isActive = false
        }

        // Activate selected profile
        profile.isActive = true
        currentProfile = profile
        
        // Save
        try modelContext.save()
        
        // Reload to ensure state is updated
        loadProfiles()
        loadActiveProfile()
        
        // Verify key access for the new profile (triggers biometric).
        // Skip verification if profile was just created (key is known to be accessible).
        //
        // Opening the handshake window *first* means this prompt IS the
        // connection's prompt: the read below fills the hold, and the auth
        // handshake that follows the switch reuses it instead of asking again.
        if !skipBiometricVerification {
            beginHandshakeUnlock()
            guard verifyKeyAccess(reason: "profile switch") else {
                endHandshakeUnlock()
                // ROLL BACK. The activation above already happened — `isActive`
                // is true, `currentProfile` is set, and it is saved — so leaving
                // it there after a failed unlock means the no-op guard at the top
                // of this function swallows every retry: the profile IS the
                // current one and IS active, so selecting it again does nothing
                // and never asks again.
                //
                // With two profiles you could stumble out of that by switching
                // away and back. With ONE, which is the common case, there is
                // nothing to switch to and the account is simply unreachable
                // until the app is reinstalled — for a cancelled Face ID prompt.
                //
                // A switch that did not complete must not look like one that did.
                profile.isActive = false
                currentProfile = nil
                try? modelContext.save()
                loadProfiles()
                loadActiveProfile()
                throw Self.readFailureReason(profileId: profile.id.uuidString)
            }
        }
    }

    /// Why a key that exists could not be read, in terms the user can act on.
    ///
    /// Every read failure used to arrive as one sentence — "authentication may
    /// have been cancelled or failed" — which is right for the common case and
    /// actively misleading for the two that matter. Someone whose Face ID was
    /// re-enrolled is not going to succeed by trying again: `.biometryCurrentSet`
    /// invalidated the key the moment the enrolment changed, and the profile is
    /// gone. Telling them to retry is telling them to keep pulling a handle that
    /// is no longer attached to anything.
    ///
    /// Compares the gate the key was WRITTEN under against what the device can
    /// do NOW — which is the comparison the old single message could not make,
    /// because the first half of it was never recorded.
    static func readFailureReason(profileId: String) -> ProfileError {
        let tier = KeyProtectionTier.stored(for: profileId)
        let capability = DeviceAuthCapability.current
        switch (tier, capability) {
        case (_, .biometryLockout), (.biometryCurrentSet, .biometryDenied):
            // Both recoverable, and telling them apart from the terminal cases
            // below is the whole reason this function reads the tier at all.
            // Revoking an app's Face ID permission changes no ENROLMENT, so it
            // cannot invalidate a `.biometryCurrentSet` key — the key is sitting
            // there intact behind a switch the user can flip back.
            return .keyTemporarilyLocked(capability)
        case (.biometryCurrentSet, _) where capability.invalidatesBiometricKeys:
            // The biometric enrolment this key was bound to is gone. MAS-8,
            // arriving in someone's hands rather than in a document.
            return .keyDestroyedByEnrolmentChange
        case (.userPresence, .none):
            return .keyDestroyedByPasscodeRemoval
        default:
            // The gate the key needs is available and it still would not open:
            // the ordinary cancelled-or-failed case.
            return .keychainAccessFailed
        }
    }
    
    /// Delete a profile
    func deleteProfile(_ profile: Profile) throws {
        // Drop any held key before removing the profile's Keychain items.
        cachedSecretKey = nil
        // Delete secret key + seed from Keychain
        deleteSecretKey(profileId: profile.id.uuidString)
        deleteSeed(profileId: profile.id.uuidString)
        // …and the at-rest message key. Its rows go with the profile (cascade),
        // and without the key they'd be unreadable anyway.
        MessageKeyStore.delete(for: profile.id)
        // Per-friend channel keys are namespaced by this profile; the cascade
        // deletes the rows but not the Keychain items behind them.
        for friend in profile.friends ?? [] { friend.clearAESKeys() }
        // …and this profile's own published prekey secrets. They are not tied to
        // any one friend, so nothing above would have caught them, and they open
        // handshakes addressed to an identity that no longer exists.
        PrekeyService.clear(profileID: profile.id)
        
        // Delete from database (cascade will delete friends and messages)
        modelContext.delete(profile)
        
        // If this was the active profile, activate another one or clear
        if profile.isActive {
            if let firstProfile = profiles.first(where: { $0.id != profile.id }) {
                try switchToProfile(firstProfile)
            } else {
                currentProfile = nil
            }
        }
        
        // Save
        try modelContext.save()
        
        // Load updated list
        loadProfiles()
    }
    
    // MARK: - Biometric key access

    /// Advisory: does this profile look like it has a stored key?
    ///
    /// **Never blocks anything.** Two previous attempts to gate launch on a
    /// Keychain probe both failed on device, for opposite reasons, and each one
    /// stranded working profiles behind an error screen. The lesson is that the
    /// only reliable proof of key access is using the key — which the auth
    /// handshake does moments later, and now reports properly when it fails.
    /// So this is diagnostics, not a gate.
    ///
    /// Asking for attributes only is NOT enough. That was the belief here, and
    /// the audit log measured it prompting for 853ms — the Keychain authenticated
    /// to answer a metadata question. `UIFail` is what actually asks without
    /// asking the user: an item that exists but needs a person answers
    /// `errSecInteractionNotAllowed`, which is the answer.
    ///
    /// Not `kSecUseAuthenticationUISkip`, which the version before that used —
    /// it does not mean "tell me without asking", it drops
    /// authentication-requiring items from the search entirely, so a
    /// biometric-protected key always came back as `errSecItemNotFound`.
    @discardableResult
    func hasStoredKey() -> Bool {
        guard let profileId = currentProfile?.id.uuidString else { return false }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(Self.keychainServicePrefix).\(profileId)",
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        var item: AnyObject?
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "profile-identity-key EXISTS?",
                                            expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, &item)
        }
        if status != errSecSuccess && status != errSecInteractionNotAllowed {
            print("[ProfileManager] ℹ️ Key metadata lookup returned \(status) for profile \(profileId)")
        }
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // MARK: - Handshake unlock window

    /// How long the handshake hold survives after auth completes. The server
    /// sends the friend list the moment we authenticate, and each friend coming
    /// online can trigger an `aes` or `key_rotate` frame that needs the private
    /// key. Zeroing the hold the instant auth succeeded meant that burst
    /// re-prompted once per friend.
    private static let handshakeGrace: TimeInterval = 20

    private var handshakeUnlockUntil: Date?
    /// Drops the hold when the window expires, so the key bytes do not sit in
    /// memory waiting for the next read to notice the window has lapsed.
    private var unlockCloseTask: Task<Void, Never>?

    /// True while the connection handshake may reuse a single unlock.
    private var handshakeWindowOpen: Bool {
        guard let until = handshakeUnlockUntil else { return false }
        return Date() < until
    }

    /// Open the unlock window for something WE initiated — signing in, or
    /// switching profile. The read that follows is the one prompt for the burst
    /// of key traffic that our own action is about to cause.
    func beginHandshakeUnlock() {
        openUnlockWindow()
    }

    /// Open the window for an inbound key-dependent frame (`aes`, `key_rotate`).
    ///
    /// Deliberately does NOT extend a window that is already open. Each of those
    /// frames needs the private key, so before this existed a burst of them cost
    /// one Face ID *each* — the window was only ever opened at sign-in, and
    /// anything arriving more than `handshakeGrace` later paid its own prompt.
    ///
    /// Refusing to slide is the security half. These frames are sent by the
    /// PEER: a window that moved forward on every arrival would let a remote
    /// party keep our private key resident in memory for as long as it kept
    /// talking. Opening only when none is open bounds the hold to one
    /// `handshakeGrace` from the first frame of a burst, however long the burst
    /// runs — the cost is at most one prompt per window for a peer that keeps
    /// sending, and the key is never held because someone else decided so.
    func beginKeyBurstUnlock() {
        guard !handshakeWindowOpen else { return }
        openUnlockWindow()
    }

    private func openUnlockWindow() {
        handshakeUnlockUntil = Date().addingTimeInterval(Self.handshakeGrace)
        unlockCloseTask?.cancel()
        unlockCloseTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(Self.handshakeGrace * 1_000_000_000))
            guard !Task.isCancelled else { return }
            self?.endHandshakeUnlock()
        }
    }

    /// Close the window and drop the held key. Called once the handshake and
    /// its trailing key traffic are done, and on background / profile switch.
    func endHandshakeUnlock() {
        unlockCloseTask?.cancel()
        unlockCloseTask = nil
        handshakeUnlockUntil = nil
        if !holdsKeyForSession { cachedSecretKey = nil }
    }

    /// Drop the in-memory key hold (unsecure mode). Call on background, profile
    /// switch, or when the mode is turned off so the key isn't retained.
    func clearCachedKey() {
        unlockCloseTask?.cancel()
        unlockCloseTask = nil
        cachedSecretKey = nil
        handshakeUnlockUntil = nil
        MessageKeyStore.clearCache()
        MessageKeyGate.shared.lock()
    }

    /// Get secret key for the current profile.
    ///
    /// - Unsecure mode ON: return the in-memory hold if present, else read once
    ///   from the Keychain (one biometric prompt) and hold it for reuse.
    /// - Unsecure mode OFF (default): never hold the key — every call is a fresh
    ///   biometric-gated Keychain read (most secure; the proven path).
    /// - Unsecure mode ON: return the in-memory hold if present, else read once
    ///   from the Keychain (one biometric prompt) and hold it for reuse.
    /// - Handshake window open: same, but the hold lasts only for the window.
    /// - Otherwise (default, idle): never hold the key — every call is a fresh
    ///   biometric-gated Keychain read.
    func getSecretKey(reason: String = "key read") -> Data? {
        guard let profileId = currentProfile?.id.uuidString else {
            return nil
        }
        if holdsKeyForSession || handshakeWindowOpen {
            if let cached = cachedSecretKey { return cached }
            let key = readSecretKey(profileId: profileId, reason: reason)
            cachedSecretKey = key
            return key
        }
        // No hold applies — make sure nothing lingers, then read fresh.
        cachedSecretKey = nil
        return readSecretKey(profileId: profileId, reason: reason)
    }

    /// Verify access to the current profile's secret key (may trigger biometric
    /// authentication). Goes through `getSecretKey()` so it also primes the hold
    /// in unsecure mode.
    /// - Returns: True if key is accessible, false otherwise
    func verifyKeyAccess(reason: String = "verify key access") -> Bool {
        guard currentProfile != nil else { return false }
        return getSecretKey(reason: reason) != nil
    }

    /// One fresh-`LAContext` Keychain read of a profile's secret key: a single
    /// biometric attempt, letting the OS present the prompt and (for
    /// `.userPresence`) fall back to passcode. Reusing a context across reads
    /// caused rate-limit lockouts on device, so each read stands alone.
    /// - Parameter allowShared: false on the retry after a shared context failed,
    ///   so the fallback cannot loop.
    private func readSecretKey(profileId: String, reason: String = "key read",
                               allowShared: Bool = true) -> Data? {
        let keychainService = "\(Self.keychainServicePrefix).\(profileId)"

        // ONE unlock for the whole session, across BOTH key stores.
        //
        // A tier-1 launch used to cost two prompts — this key, then the
        // message-key gate — because each store authenticated for itself. Both of
        // a profile's keys carry the same tier, so a context that satisfied one
        // satisfies the other. Whichever store asks first raises the single
        // prompt and publishes the result; the other rides it.
        //
        // Only for a tier that holds. On tier 2 the whole point is to ask again,
        // and sharing a context there would quietly convert the secure default
        // into the convenient one.
        let shared = (allowShared && activeTier.holdsKeyForSession)
            ? MessageKeyStore.sharedAuthenticatedContext() : nil

        // One line per Keychain read is one line per prompt the user sees. When
        // someone reports "it asked me twice", this log says which two moments
        // asked — and a ridden context logs no prompt because it raises none.
        if shared == nil {
            Self.promptCount += 1
            print("[ProfileManager] 🔐 auth prompt #\(Self.promptCount) — \(reason)")
        }

        let context = shared ?? LAContext()
        context.localizedReason = "Access your private key"
        // Announce the prompt so an async unlock does not raise a second one
        // beside it — iOS would cancel one of the two. See BiometricCoordinator.

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]

        var result: AnyObject?
        let status = BiometricCoordinator.withPrompt {
            BiometricAudit.measure("SecItemCopyMatching",
                                   item: "profile-identity-key \(profileId.prefix(8))…",
                                   expectsPrompt: true) {
                SecItemCopyMatching(query as CFDictionary, &result)
            }
        }
        guard status == errSecSuccess,
              let data = result as? Data else {
            // A shared context that did not open this key must never leave
            // someone locked out over an optimisation. Drop it and ask properly:
            // one extra prompt in the worst case, which is exactly what this cost
            // before the two stores shared anything.
            if shared != nil {
                print("[ProfileManager] ↻ shared context did not open the key (\(status)) — asking directly")
                MessageKeyStore.discardAuthenticatedContext()
                return readSecretKey(profileId: profileId, reason: reason, allowShared: false)
            }
            return nil
        }
        // Ours satisfied the user. Hand it over so the message gate opens without
        // asking again.
        if activeTier.holdsKeyForSession, shared == nil {
            MessageKeyStore.adoptAuthenticatedContext(context)
        }
        return data
    }
    
    /// Store secret key in Keychain for a profile with biometric protection
    private func storeSecretKey(_ secretKey: Data, profileId: String,
                                tier: KeyProtectionTier) throws {
        let keychainService = "\(Self.keychainServicePrefix).\(profileId)"
        print("[ProfileManager] Storing key for service: \(keychainService) (tier \(tier.rawValue))")
        
        // Delete existing item if present
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService
        ]
        
        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        if deleteStatus == errSecSuccess {
            print("[ProfileManager] Deleted existing keychain item")
        } else if deleteStatus != errSecItemNotFound {
            print("[ProfileManager] ⚠️ Warning: Failed to delete existing item: \(deleteStatus)")
        }
        
        // Access control is mandatory. There is no unprotected path out of this
        // function on any platform.
        var error: Unmanaged<CFError>?
        
        // ONE flag, chosen by the CALLER and never here. `tier` arrives already
        // decided — from `DeviceAuthCapability.current`, and for the weak tier
        // only after the user confirmed a prompt that named what is weaker. That
        // is the whole difference between this and the ladder e22ecd7 removed:
        // this function cannot downgrade anything, because it does not choose.
        //
        // Tier 2, `.biometryCurrentSet`, is the default and the strong one. It
        // binds the key to the biometric enrolment that existed when it was
        // written, so someone who learns the passcode cannot enrol their own face
        // and read it (Semgrep keychain-acl-allows-biometry-changes). The cost is
        // that re-enrolling Face ID destroys this key and with it the account —
        // MAS-8, still open, still a release blocker until there is a recovery
        // path.
        //
        // Tier 1, `.devicePasscode`, exists because the alternative was not a
        // stronger key. It was -25293 on the welcome screen and no account at
        // all. See `KeyProtectionTier.accessControlFlag` for why this is not the
        // OR'd passcode arm Semgrep looks for.
        //
        // Fail loudly on EVERY platform rather than silently storing the identity
        // key unprotected. macOS used to take a second branch here and carry on
        // with `useBiometric = false`, which is the other half of APP-2: the Mac
        // build quietly held the key behind nothing but first unlock.
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            tier.accessControlFlag,
            &error
        ) else {
            print("[ProfileManager] ❌ Could not create access control: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
            throw ProfileError.keychainStoreFailed(errSecParam)
        }

        // ONE literal, with the access control in it. It used to be built in
        // pieces — `addQuery[kSecAttrAccessControl] = accessControl` on its own
        // line, against an OPTIONAL — and that is a quiet trapdoor: assigning nil
        // through a Dictionary subscript REMOVES the key, so a nil that slipped
        // past the guard would have stored the identity key with no access
        // control at all and no error to show for it. Exactly APP-2, rebuilt by
        // accident. Unwrapped above, inline here, and now impossible to express.
        //
        // It also means a reader — human or scanner — can see the protection and
        // the store in one expression instead of tracing a mutation.
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecValueData as String: secretKey,
            kSecAttrAccessControl as String: accessControl
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            print("[ProfileManager] ❌ Failed to add keychain item: \(status) — "
                  + ProfileError.explain(status))
            // The marker must never outlive the key it describes. A stale one
            // would tell a later read that a key which is not there was written
            // under some tier, which is a lie the read path would act on.
            KeyProtectionTier.deleteMarker(for: profileId)
            throw ProfileError.keychainStoreFailed(status)
        }

        // Written AFTER the key and only on success, so the marker's existence
        // means "a key exists and this is its gate" rather than "someone tried".
        KeyProtectionTier.storeMarker(tier, for: profileId)
        
        print("[ProfileManager] ✅ Keychain item added — tier \(tier.rawValue), \(tier.detail)")
    }
    
    /// Delete secret key from Keychain
    private func deleteSecretKey(profileId: String) {
        let keychainService = "\(Self.keychainServicePrefix).\(profileId)"
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        KeyProtectionTier.deleteMarker(for: profileId)
    }
}

enum ProfileError: LocalizedError {
    case randomGenerationFailed
    case keychainStoreFailed(OSStatus)
    case invalidSeed
    case profileNotFound
    case keychainAccessFailed
    /// Nothing on this device can gate a key — no passcode, or biometrics are
    /// locked out. Raised BEFORE any key material is generated.
    case deviceCannotProtectKey(DeviceAuthCapability)
    /// A caller asked to create at the reduced tier without the user's consent.
    /// A programming error, surfaced rather than silently honoured.
    case downgradeNotConsented(DeviceAuthCapability)
    /// A caller asked for a STRONGER gate than the device can deliver. Refused
    /// rather than quietly satisfied with a weaker one.
    case tierUnavailable(DeviceAuthCapability)
    /// The key is intact; the device just will not authenticate right now.
    case keyTemporarilyLocked(DeviceAuthCapability)
    /// `.biometryCurrentSet` did what it promises. Terminal.
    case keyDestroyedByEnrolmentChange
    /// The passcode a tier-1 key was bound to is gone. Terminal.
    case keyDestroyedByPasscodeRemoval

    /// What an OSStatus from `SecItemAdd` actually means.
    ///
    /// This mapping existed already, one line above the throw, and was printed
    /// to the console and discarded — so the console knew "Authentication
    /// failed" while the alert showed the user "-25293". Lifting it here is the
    /// smallest part of this change and the one that would have turned a bug
    /// report into a self-diagnosis.
    static func explain(_ status: OSStatus) -> String {
        switch status {
        case errSecDuplicateItem:
            return "A key for this profile already exists."
        case errSecAuthFailed:
            return "This device could not authenticate you. Face ID, Touch ID, or a device passcode must be set up."
        case errSecInteractionNotAllowed:
            return "The device was locked. Unlock it and try again."
        case errSecMissingEntitlement:
            return "This build is missing the Keychain entitlement needed for biometric protection."
        default:
            return "The Keychain refused to store the key."
        }
    }

    var errorDescription: String? {
        switch self {
        case .randomGenerationFailed:
            return "Failed to generate random seed"
        case .keychainStoreFailed(let status):
            // Sentence first, code in parentheses. The code is for a bug report;
            // the sentence is for the person holding the phone.
            return "\(Self.explain(status)) (Keychain status \(status))"
        case .invalidSeed:
            return "Invalid seed format or size"
        case .profileNotFound:
            return "Profile not found"
        case .keychainAccessFailed:
            return "Failed to access private key. Biometric authentication may have been cancelled or failed."
        case .deviceCannotProtectKey(let capability):
            return "\(capability.headline) \(capability.remedy)"
        case .downgradeNotConsented(let capability):
            return "\(capability.headline) Reduced protection has to be confirmed before a profile can be created."
        case .tierUnavailable(let capability):
            return "\(capability.headline) \(capability.remedy)"
        case .keyTemporarilyLocked(let capability):
            return "\(capability.headline) \(capability.remedy)"
        case .keyDestroyedByEnrolmentChange:
            return "This profile's key was locked to the Face ID or Touch ID enrolment that existed when it was created, and that enrolment has changed. The key is permanently unreadable and the profile cannot be opened on this device."
        case .keyDestroyedByPasscodeRemoval:
            return "This profile's key was protected by the device passcode, and that passcode has been removed. The key is permanently unreadable."
        }
    }

    /// Whether trying again could plausibly work. Terminal errors must not be
    /// dressed up as retryable — that is what sends someone round a loop that
    /// cannot close.
    var isRecoverable: Bool {
        switch self {
        case .keyDestroyedByEnrolmentChange, .keyDestroyedByPasscodeRemoval:
            return false
        default:
            return true
        }
    }
}

