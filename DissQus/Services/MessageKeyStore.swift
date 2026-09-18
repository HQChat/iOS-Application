//
//  MessageKeyStore.swift
//  DissQus
//
//  The at-rest protection for message bodies — and the one place in the app
//  where "write without the user" and "read only with the user" have to hold at
//  the same time.
//
//  WHY IT IS ASYMMETRIC (threat model TM-3). The first version was a single
//  256-bit key per profile, held in the Keychain as
//  `AfterFirstUnlockThisDeviceOnly` with no access control. That flag was not an
//  oversight: a message arriving while the app is backgrounded has to be sealed
//  with no human present, and a biometric prompt cannot be raised there. But it
//  meant the biometric gate users associate with this app protected the identity
//  key only — anything able to read the Keychain after the device's first unlock
//  read the entire archive without ever touching the HQC private key.
//
//  A symmetric key cannot satisfy both requirements: the same bytes that seal a
//  message open it. So the scheme is hybrid public-key:
//
//    seal   AES-GCM(body, Km) with a fresh random Km, then ECIES-wrap Km to the
//           PUBLIC key. Needs no authentication — background receives are
//           unaffected.
//    open   ECIES-unwrap Km with the PRIVATE key, which is `.userPresence`
//           gated, then AES-GCM open. Needs the user.
//
//  One `LAContext` can be reused across many unwraps, so opening a conversation
//  costs one prompt, not one per row.
//
//  Deleting a profile deletes its key pair, which makes that profile's rows
//  permanently unreadable. That is the point, and it is unchanged.
//

import Foundation
import CryptoKit
import LocalAuthentication
#if canImport(UIKit)
import UIKit
#endif

enum MessageKeyStore {
    /// Distinct from `AESKeyStore`'s service so a profile wipe can drop message
    /// keys without touching per-friend channel keys.
    static let service = "com.dissqus.messagekeys"

    /// ECIES variant used for both directions. Available on iOS 13+/macOS 10.15+.
    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM

    private static func tag(_ profileID: UUID) -> Data {
        Data("com.dissqus.messagekey.\(profileID.uuidString)".utf8)
    }
    /// The account the deleted symmetric floor used to occupy. Kept only so
    /// `delete(for:)` still clears one left behind by an older build — nothing
    /// writes or reads it as a key any more.
    private static func retiredFallbackAccount(_ profileID: UUID) -> String { "msg.\(profileID.uuidString)" }

    /// Public keys are cheap to hold and carry no authority — caching them keeps
    /// the seal path off the Keychain entirely after first use.
    private static var publicCache: [UUID: SecKey] = [:]
    /// Legacy symmetric keys, for rows sealed before the migration.
    private static let lock = NSLock()

    /// The context that one successful `evaluatePolicy` produced.
    ///
    /// Unwrapping needs an ALREADY-authenticated context — that is the whole
    /// mechanism `kSecUseAuthenticationContext` provides, and passing a bare one
    /// is what drove the Keychain into a rate-limit lockout (#79). So the prompt
    /// happens once, deliberately, from `authenticateForReading`, and every
    /// synchronous read afterwards rides on the result without prompting.
    ///
    /// While this is nil, reads return nil rather than authenticating. That is
    /// the point: `Message.content` is a computed property read from view
    /// bodies, and a property SwiftUI may evaluate at any moment must never be
    /// able to raise a prompt.
    private static var readContext: LAContext?

    /// The profile whose key the read unlock has to satisfy.
    ///
    /// The gate is app-wide; the KEY is not. Which `LAPolicy` produces a context
    /// the Keychain will accept depends on the tier this profile's key was
    /// written under, and asking for the wrong one is the trap e22ecd7 fixed in
    /// the other direction: the user completes an unlock and every row stays
    /// locked with nothing on screen to explain it.
    ///
    /// Set by `ProfileManager` wherever the active profile is settled. Nil reads
    /// as the strong tier, which is what every profile written before tiers
    /// existed actually carries.
    private static var activeProfileID: UUID?

    static func setActiveProfile(_ id: UUID?) {
        lock.lock(); defer { lock.unlock() }
        activeProfileID = id
    }

    /// The tier the current unlock must authenticate against.
    private static var activeTier: KeyProtectionTier {
        lock.lock()
        let id = activeProfileID
        lock.unlock()
        guard let id else { return .biometryCurrentSet }
        return KeyProtectionTier.stored(for: id.uuidString)
    }

    /// The session's authenticated context, for a tier that unlocks once.
    ///
    /// Handed to `ProfileManager` so a tier-1 launch costs ONE prompt across both
    /// key stores rather than one each. Both of a profile's keys carry the same
    /// tier, so a context that satisfied one satisfies the other.
    static func sharedAuthenticatedContext() -> LAContext? {
        lock.lock(); defer { lock.unlock() }
        return lockedOut ? nil : readContext
    }

    /// Adopt a context that has already satisfied the user elsewhere, so this
    /// store does not raise a second prompt for the same session.
    static func adoptAuthenticatedContext(_ context: LAContext) {
        lock.lock()
        let fresh = readContext == nil && !lockedOut
        if fresh {
            readContext = context
            promptWindows += 1
        }
        let window = promptWindows
        lock.unlock()
        if fresh {
            print("[MessageKeyStore] 🔓 read unlocked by the identity-key unlock (window #\(window))")
        }
    }

    /// Drop a shared context that turned out not to open a key. The caller then
    /// authenticates properly rather than leaving the user stuck behind an
    /// optimisation.
    static func discardAuthenticatedContext() {
        lock.lock(); defer { lock.unlock() }
        readContext?.invalidate()
        readContext = nil
    }

    /// Whether a synchronous read can succeed right now.
    static var canRead: Bool {
        lock.lock(); defer { lock.unlock() }
        return readContext != nil && !lockedOut
    }

    /// What one unlock attempt settled.
    enum UnlockOutcome {
        /// Authenticated; synchronous reads will now succeed.
        case granted
        /// The user said no. Stop asking until something changes.
        case refused
        /// Nobody decided — the system took the hardware, most often because
        /// another prompt (sign-in) was raised at the same moment. Ask again.
        case interrupted
    }

    /// Authenticate once, so a whole screen of rows can be opened without a
    /// prompt each. Call before showing message bodies; safe to call again.
    static func authenticateForReading(reason: String) async -> UnlockOutcome {
        if canRead { return .granted }

        // No profile, no message keys, nothing to unlock — and yet this asked.
        // `MessageKeyGate.unlock()` is called from the scene handler on every
        // `.active`, which includes sitting on the welcome screen before any
        // profile exists. The user got a Face ID prompt for an empty database,
        // and on the creation path it landed straight into the middle of the
        // consent prompt, which is one half of "two codes are prompted".
        guard activeProfileID != nil else { return .refused }

        let tier = activeTier

        // On a tier that unlocks ONCE for the session, do not race the identity
        // read to the prompt.
        //
        // At launch both start within a frame of each other: the scene handler
        // asks for the message unlock while sign-in reads the identity key.
        // Whichever got there second raised a SECOND sheet, iOS cancelled one of
        // them, and the user answered a prompt only to be told it was cancelled —
        // on the very tier whose entire promise is "one unlock per launch".
        //
        // So wait for the identity read to publish its context instead of
        // competing with it. Bounded: if no sign-in is coming — a plain return to
        // the foreground — this falls through and asks, which is correct.
        if tier.holdsKeyForSession {
            let deadline = Date().addingTimeInterval(Self.waitForSharedUnlock)
            while !canRead, Date() < deadline {
                if BiometricCoordinator.isBusy || Self.sharedAuthenticatedContext() == nil {
                    do { try await Task.sleep(nanoseconds: 200_000_000) } catch { return .interrupted }
                } else {
                    break
                }
            }
            if canRead { return .granted }
        }

        // Announce OUR prompt, so the synchronous side does not raise one beside
        // it. Paired with `end()` below on every path out.
        BiometricCoordinator.begin()
        defer { BiometricCoordinator.end() }

        let context = LAContext()
        // Set BEFORE evaluating, or it does not apply.
        //
        // One `evaluatePolicy` is not one prompt. Every row still runs its own
        // `SecKeyCreateDecryptedData` against the `.userPresence` key, and with
        // the default reuse duration of 0 each of those can re-authenticate — a
        // burst of prompts with a single "read unlocked" line to account for
        // them, because only the policy evaluation was ever logged.
        //
        // This is NOT the mistake #79 undid. That reused a context which had
        // never been authenticated at all, so every Keychain call tried to
        // authenticate through it and tripped the rate limiter. This one has
        // satisfied `evaluatePolicy` first; the duration only says how long that
        // success keeps counting.
        //
        // The real bound is `clearCache()`, which invalidates the context on
        // background and on profile switch — both sooner than this ceiling.
        context.touchIDAuthenticationAllowableReuseDuration =
            LATouchIDAuthenticationMaximumAllowableReuseDuration
        do {
            let ok = try await BiometricAudit.measureAsync("LAContext.evaluatePolicy",
                                                           item: "message-read unlock",
                                                           expectsPrompt: true) {
                // nosemgrep: swift.biometrics-and-auth.local-biometrics.insecure-biometrics
                // The rule's concern is a boolean that GRANTS access, hookable
                // with Frida. This boolean grants nothing. What it produces is an
                // authenticated `LAContext`, and the access comes from the
                // Keychain honouring that context against the key's ACL — which
                // it verifies itself, not from `ok` being true.
                //
                // Not a claim, an observation: #79 passed a context that had never
                // been authenticated and the Keychain refused every operation,
                // eventually rate-limiting with "Reached maximum count of
                // authentication attempts". A spoofed `true` lands in exactly that
                // state. The rule's advice — authenticate via Keychain Services —
                // is what the next line down already does; `evaluatePolicy` is
                // here to authenticate the context ONCE so a screenful of rows
                // costs one prompt rather than one each.
                //
                // The policy has to ask for what the key needs, and what the
                // key needs is recorded rather than guessed. A tier-2 key is
                // `.biometryCurrentSet` and a passcode success would hand back a
                // context that cannot open it — an unlock the user completed,
                // followed by rows that stay locked for no visible reason. A
                // tier-1 key is the exact mirror: ask WithBiometrics on a device
                // that has none enrolled and the evaluation cannot even be made.
                try await context.evaluatePolicy(tier.policy, localizedReason: reason)
            }
            guard ok else { return .refused }
            lock.lock()
            readContext = context
            lockedOut = false
            promptWindows += 1
            lock.unlock()
            print("[MessageKeyStore] 🔓 read unlocked (window #\(promptWindows))")
            return .granted
        } catch let error as LAError {
            let outcome: UnlockOutcome
            switch error.code {
            case .userCancel, .userFallback, .authenticationFailed,
                 .biometryLockout, .passcodeNotSet, .biometryNotEnrolled:
                outcome = .refused
            default:
                // .systemCancel and .appCancel above all: the evaluation was
                // taken away from us, not turned down.
                outcome = .interrupted
            }
            print("[MessageKeyStore] 🔒 unlock \(outcome) — \(error.localizedDescription)")
            return outcome
        } catch {
            print("[MessageKeyStore] 🔒 unlock interrupted — \(error.localizedDescription)")
            return .interrupted
        }
    }

    /// How long a holding tier waits for the identity read to publish its
    /// context before asking for its own. Long enough to cover a sign-in that is
    /// already in flight, short enough that a foreground return with no sign-in
    /// coming does not feel stuck.
    private static let waitForSharedUnlock: TimeInterval = 6

    /// Set when the OS refuses further authentication attempts.
    ///
    /// `SecKeyCreateDecryptedData` on a `.userPresence` key authenticates, and
    /// the Keychain rate-limits that: hammering it produces
    ///
    ///   Reached maximum count of authentication attempts
    ///   operation: od acl:…DeviceOwnerAuthentication
    ///
    /// after which every further call fails AND costs another attempt. Nothing
    /// stopped, so a screenful of rows drove the store further into lockout.
    /// While this is set, `unwrap` returns nil without touching the Keychain.
    private static var lockedOut = false

    /// So an ACL refusal on a key we cannot repair is reported once, not once
    /// per row.
    private static var aclRefusalAnnounced = false

    /// True when the store has stopped trying because the OS refused. Callers
    /// use it to tell "this row cannot be read" from "this row is not readable
    /// right now" — the second must not be cached as if it were the first.
    static var isLockedOut: Bool {
        lock.lock(); defer { lock.unlock() }
        return lockedOut
    }

    /// How many authentication windows have been opened — i.e. roughly how many
    /// prompts this store has cost the user. Diagnostics only, and deliberately
    /// distinct from `ProfileManager`'s counter: the two prompt for DIFFERENT
    /// Keychain items, and telling them apart is the first question to answer
    /// when someone reports being asked too often.
    private static var promptWindows = 0

    // MARK: - Sealing (no authentication)

    /// This profile's public key, creating the key pair on first use.
    static func publicKey(for profileID: UUID) -> SecKey? {
        lock.lock()
        defer { lock.unlock() }
        if let cached = publicCache[profileID] { return cached }
        // Stored copy first: no private key, no ACL, no prompt.
        if let stored = loadStoredPublicKey(profileID) {
            publicCache[profileID] = stored
            return stored
        }
        // Not stored yet — a profile created before the public half had its own
        // home. Derive it once and persist, so this is the last time sealing
        // depends on the private key being reachable. `privateKeyRef` will not
        // prompt: without an unlocked context it simply fails, and the caller
        // falls back to the symmetric seal until the next unlock backfills this.
        guard let priv = privateKeyRef(profileID, context: nil) ?? createKeyPair(profileID),
              let pub = SecKeyCopyPublicKey(priv) else { return nil }
        storePublicKey(pub, for: profileID)
        publicCache[profileID] = pub
        return pub
    }

    // MARK: - Key scheme

    /// The scheme the CURRENT code creates key pairs under.
    ///
    /// 1 — Secure Enclave, `.biometryCurrentSet` only. Unusable: the ACL permits
    ///     no private-key operation, so the ECIES unwrap is refused with
    ///     `-1009 ACL operation is not allowed: 'ock'`. Shipped briefly; every
    ///     key written under it can seal and can never open.
    /// 2 — the same, plus `.privateKeyUsage`. Works.
    ///
    /// Keys written before any of this carry no marker and read as 0. Those are
    /// ordinary Keychain keys rather than Enclave ones, and are perfectly usable
    /// — which is exactly why the repair below must not fire on them blindly.
    private static let currentKeyScheme = 2

    private static func schemeAccount(_ profileID: UUID) -> String { "scheme.\(profileID.uuidString)" }

    /// Which scheme a profile's existing key pair was made under.
    private static func keyScheme(_ profileID: UUID) -> Int {
        guard let data = readItem(schemeAccount(profileID)), let first = data.first else { return 0 }
        return Int(first)
    }

    /// `SecKeyCreateDecryptedData` refusing the OPERATION rather than the user.
    /// LocalAuthentication's domain, and not one of the public `LAError` cases —
    /// the string that comes with it is `ACL operation is not allowed: '<op>'`.
    private static let aclOperationNotAllowed = -1009

    /// Regenerated profiles, so a broken key is rebuilt once and not once per row.
    private static var repairedProfiles: Set<UUID> = []

    /// Throw away a key pair that cannot perform private-key operations at all,
    /// and make one that can.
    ///
    /// This destroys the ability to read anything sealed under the old key —
    /// which costs nothing, because a scheme-1 key could never have opened those
    /// rows either. They were unreadable the moment they were written, and this
    /// only stops new ones joining them. Deliberately narrow: it runs on the
    /// specific ACL refusal, and only for a key whose marker says it came from
    /// the broken scheme.
    private static func regenerateBrokenKeyPair(_ profileID: UUID) {
        lock.lock()
        let alreadyDone = repairedProfiles.contains(profileID)
        if !alreadyDone { repairedProfiles.insert(profileID) }
        publicCache[profileID] = nil
        lock.unlock()
        guard !alreadyDone else { return }

        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrApplicationTag as String: tag(profileID)
        ] as CFDictionary)

        let replaced = createKeyPair(profileID) != nil
        print("[MessageKeyStore] 🔧 regenerated the message key for "
              + "\(profileID.uuidString.prefix(8))… — the old one was created without "
              + "`.privateKeyUsage`, so the Secure Enclave refused every use of it. "
              + (replaced ? "Replaced." : "REPLACEMENT FAILED.")
              + " Messages already stored stay unreadable; they always were.")
    }

    /// Keychain account holding the PUBLIC half, in the clear.
    ///
    /// A public key protects nothing and needs no protection — but it used to be
    /// reachable only by fetching the private key's reference, which meant
    /// sealing an outgoing message could raise a biometric prompt. Storing it
    /// separately is what makes the write path genuinely user-free, which is the
    /// property §4.6 claims for it.
    private static func publicAccount(_ profileID: UUID) -> String { "pub.\(profileID.uuidString)" }

    private static func storePublicKey(_ pub: SecKey, for profileID: UUID) {
        guard let data = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { return }
        writeItem(data, account: publicAccount(profileID))
    }

    private static func loadStoredPublicKey(_ profileID: UUID) -> SecKey? {
        guard let data = readItem(publicAccount(profileID)) else { return nil }
        return SecKeyCreateWithData(data as CFData, [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ] as CFDictionary, nil)
    }

    /// Wrap a per-message key to the profile's public key. No prompt.
    static func wrap(_ messageKey: SymmetricKey, for profileID: UUID) -> Data? {
        guard let pub = publicKey(for: profileID) else { return nil }
        let raw = messageKey.withUnsafeBytes { Data($0) }
        var error: Unmanaged<CFError>?
        guard let wrapped = SecKeyCreateEncryptedData(pub, algorithm, raw as CFData, &error) as Data? else {
            return nil
        }
        return wrapped
    }

    // MARK: - Opening (requires the user)

    /// Unwrap a per-message key. Raises the biometric/passcode prompt unless
    /// `context` is an already-authenticated `LAContext` — pass one when opening
    /// a conversation so a screenful of rows costs a single prompt.
    static func unwrap(_ wrapped: Data, for profileID: UUID, context: LAContext? = nil) -> SymmetricKey? {
        // Refuse to add to the pile. Once the OS has said "maximum count of
        // authentication attempts", every further call fails and counts against
        // the limit again, so retrying is worse than useless.
        if isLockedOut { return nil }
        lock.lock()
        let auth = context ?? readContext
        lock.unlock()
        // No authenticated context: the caller has not unlocked yet. Return nil
        // instead of prompting — see `readContext`.
        guard let auth else { return nil }

        guard let priv = privateKeyRef(profileID, context: auth) else { return nil }
        var error: Unmanaged<CFError>?
        let raw = BiometricAudit.measure("SecKeyCreateDecryptedData",
                                         item: "message-key (per row)",
                                         expectsPrompt: false) {
            SecKeyCreateDecryptedData(priv, algorithm, wrapped as CFData, &error) as Data?
        }
        if raw == nil {
            let cfError = error?.takeRetainedValue()
            let code = cfError.map { CFErrorGetCode($0) }
            let domain = cfError.map { CFErrorGetDomain($0) as String } ?? ""

            // Not every failure here is the same failure, and treating them as
            // one is what let a single bad row lock a whole screen. `lockedOut`
            // stops EVERY subsequent unwrap until the next foreground, so it may
            // only be set for the condition it was written for — the OS refusing
            // further authentication attempts, where retrying really does make
            // things worse.
            // `CFErrorGetCode` is a `CFIndex`; the Security codes are `OSStatus`.
            // Widened here so the cases below can be read side by side.
            switch code ?? 0 {
            case aclOperationNotAllowed where domain == "com.apple.LocalAuthentication":
                // Structural. The key's ACL does not permit the operation, so no
                // amount of authenticating changes it and no other row will fare
                // better. Not a lockout: nothing is being rate-limited, and
                // latching one would render the rows as "locked" when the truth
                // is that this key can never open them.
                if keyScheme(profileID) < currentKeyScheme {
                    regenerateBrokenKeyPair(profileID)
                } else {
                    lock.lock()
                    let announced = aclRefusalAnnounced
                    aclRefusalAnnounced = true
                    lock.unlock()
                    if !announced {
                        print("[MessageKeyStore] 🛑 the Secure Enclave refused a private-key "
                              + "operation on a scheme-\(currentKeyScheme) key, which HAS "
                              + "`.privateKeyUsage`. The flag is not the problem — the "
                              + "authentication context is what the SEP is turning down.")
                    }
                }
            case Int(errSecAuthFailed), Int(errSecInteractionNotAllowed), Int(errSecUserCanceled):
                lock.lock()
                lockedOut = true
                promptWindows += 1
                lock.unlock()
                print("[MessageKeyStore] 🔒 authentication refused (code \(code.map(String.init) ?? "?")) — "
                      + "not retrying until the next unlock")
            default:
                // A wrong or corrupt envelope: this row cannot be opened, and
                // that says nothing about the next one. Reported per row rather
                // than latched.
                print("[MessageKeyStore] ⚠️ could not unwrap one message key "
                      + "(domain \(domain), code \(code.map(String.init) ?? "?")) — this row only")
            }
            return nil
        }
        guard let raw, raw.count == 32 else { return nil }
        // Counted because these are the operations that can prompt WITHOUT any
        // other line appearing. If this number tracks what the user sees, the
        // authentication is not covering them and the reuse window is the thing
        // to look at.
        lock.lock()
        keyUnwraps += 1
        let total = keyUnwraps
        lock.unlock()
        if total == 1 || total % 10 == 0 {
            print("[MessageKeyStore] 🔑 message keys unwrapped: \(total) (auth windows: \(promptWindows))")
        }
        return SymmetricKey(data: raw)
    }

    /// How many per-row key unwraps have run. See the note where it is bumped.
    private static var keyUnwraps = 0

    // MARK: - Lifecycle

    /// True when this profile has key material of either generation, without
    /// minting any. Used by the read path and the migration.
    static func hasKey(for profileID: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if publicCache[profileID] != nil { return true }
        if loadStoredPublicKey(profileID) != nil { return true }
        // Ask whether the key pair EXISTS without asking to use it. With
        // `UIFail`, an item that is present but needs a user answers
        // `errSecInteractionNotAllowed` — which is the answer, and costs nothing.
        // This ran through `privateKeyRef` before, once per message row, and was
        // the single largest source of prompts in the app.
        let probe: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrApplicationTag as String: tag(profileID),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: false,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "message-key PAIR EXISTS?",
                                            expectsPrompt: false) {
            SecItemCopyMatching(probe as CFDictionary, nil)
        }
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Drop everything for a profile. Call when the profile itself is deleted.
    static func delete(for profileID: UUID) {
        lock.lock()
        defer { lock.unlock() }
        publicCache[profileID] = nil
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrApplicationTag as String: tag(profileID)
        ] as CFDictionary)
        // Every generic-password item this store owns for the profile. The
        // public half used to survive a delete, and `hasKey` answers true on a
        // stored public alone — so a deleted profile still looked keyed, and
        // sealing would wrap to a public key whose private half was gone.
        for account in [retiredFallbackAccount(profileID),
                        publicAccount(profileID),
                        schemeAccount(profileID)] {
            SecItemDelete([
                kSecClass as String: kSecClassGenericPassword,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account
            ] as CFDictionary)
        }
    }

    /// Forget in-memory copies (Keychain items survive). Called on profile switch
    /// so one profile's key cannot serve another's rows.
    static func clearCache() {
        lock.lock()
        defer { lock.unlock() }
        publicCache.removeAll()
        // A new foreground or a new profile is a fresh chance: the refusal was
        // about attempt rate, not about this device being unable to authenticate.
        lockedOut = false
        // The authentication does not survive either. Backgrounding is exactly
        // when it must not, and a switch must never let one profile's unlock
        // open another's rows.
        readContext?.invalidate()
        readContext = nil
    }

    // MARK: - Symmetric fallback (devices without a user credential)

    // MARK: - Keychain

    /// The private key reference. Fetching a reference does NOT authenticate —
    /// only *using* it does — so the seal path can derive the public key from it
    /// without a prompt.
    private static func privateKeyRef(_ profileID: UUID, context: LAContext?) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrApplicationTag as String: tag(profileID),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        // The comment that used to sit here said fetching a reference does not
        // authenticate, only using it does. That is false for a `.userPresence`
        // key, and the audit log proved it: six prompts in one launch, all from
        // this line, every one of them from a caller that believed it was free.
        //
        // So a call that did not bring a context does not get to raise a prompt.
        // It rides the unlocked one if there is one, and is refused otherwise.
        if let context = context ?? readContext {
            query[kSecUseAuthenticationContext as String] = context
        } else {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        }
        var result: AnyObject?
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "message-key REF",
                                            expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, &result)
        }
        guard status == errSecSuccess else { return nil }
        // swiftlint:disable:next force_cast
        return (result as! SecKey?)
    }

    private static func createKeyPair(_ profileID: UUID) -> SecKey? {
        // `.biometryCurrentSet` so that re-enrolling a face or finger invalidates
        // this key rather than granting the new enrolment access to message
        // history (Semgrep keychain-acl-allows-biometry-changes). Re-enrolment
        // therefore makes history permanently unreadable — accepted while nothing
        // is distributed.
        //
        // The tier is the one `ProfileManager` recorded for this profile's
        // IDENTITY key, so both of a profile's keys are gated the same way. They
        // have to be: an identity key a passcode-only device can open, paired
        // with a message key it cannot, is an account that signs in and then
        // shows nothing — and the symmetric floor that used to sit under this is
        // gone (Message.swift, "There used to be a symmetric fallback here").
        //
        // Still never an OR'd `[.biometryCurrentSet, .devicePasscode]`, which is
        // what Semgrep keychain-passcode-fallback is actually looking for and
        // what would let the attacker `.biometryCurrentSet` guards against read
        // history directly. Never a bare accessibility flag either: that is the
        // state TM-3 describes.
        //
        // `.privateKeyUsage` is not optional and not decoration. A Secure
        // Enclave key's access control lists the OPERATIONS the key may perform,
        // and without this flag that list does not include private-key use at
        // all. Creation still succeeds — `SecKeyCreateRandomKey` returns a
        // perfectly good key reference — and every use of it is then refused by
        // the SEP:
        //
        //   SecKeyCreateDecryptedDataWithParameters failed:
        //   Error Domain=com.apple.LocalAuthentication Code=-1009
        //   "ACL operation is not allowed: 'ock'"
        //
        // `'ock'` is the ECDH key agreement the ECIES unwrap runs. Measured on
        // an iPhone 17: 7.9ms, silent, no prompt — the operation was not turned
        // down by a user, it was never permitted. So the key sealed every
        // outgoing message (the public half needs no ACL) and could open none of
        // them, which reads on screen as messages that never arrive.
        let tier = KeyProtectionTier.stored(for: profileID.uuidString)
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, tier.accessControlFlag], nil
        ) else { return nil }

        // Generated INSIDE the Secure Enclave, unconditionally and with no
        // fallback. The private half never exists in memory the OS can hand out,
        // so it cannot be dumped or copied even from a jailbroken device — only
        // used, for the ECIES unwrap below. P-256 with
        // `.eciesEncryptionCofactorX963SHA256AESGCM` is exactly what the Enclave
        // supports, so this needs no change to the scheme.
        //
        // The cost is stated plainly because it is not small: SE key creation
        // FAILS where there is no Enclave to create in. Measured, before this was
        // written — iOS Simulator 26.5 returns -25293, and an unsigned macOS
        // binary (which is what tests/run.sh builds) returns -25308. Nothing here
        // papers over that. A build that cannot reach an Enclave cannot make this
        // key, and the caller deals with it.
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            // REQUIRED on macOS. A Secure Enclave key can only be added to the
            // data protection keychain, and macOS defaults to the file-based one
            // — where the add fails with -34018, `errSecMissingEntitlement`,
            // "failed to add key to keychain: <SecKeyRef:('com.apple.setoken')>".
            // Measured on an Apple Silicon Mac: the Enclave was reached, the key
            // was made, and only the STORE was refused. On iOS this flag is what
            // the platform does anyway.
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag(profileID),
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        let created = BiometricAudit.measure("SecKeyCreateRandomKey",
                                             item: "message-key PAIR (create)",
                                             expectsPrompt: false) {
            SecKeyCreateRandomKey(attrs as CFDictionary, &error)
        }
        if created == nil {
            // Named, because "no Secure Enclave key for this profile" was the
            // only thing the app said while a Mac silently stored no message at
            // all — sent or received. The code is the whole diagnosis.
            let code = (error?.takeRetainedValue()).map { CFErrorGetCode($0) } ?? 0
            let meaning: String
            switch code {
            case -34018:
                meaning = "errSecMissingEntitlement — the app is signed WITHOUT an "
                    + "application identifier or keychain access group, so the data "
                    + "protection keychain (the only one that can hold an Enclave key) "
                    + "is closed to it. Signing config, not code"
            case -25293: meaning = "errSecAuthFailed — no Enclave here (Simulator)"
            case -25308: meaning = "errSecInteractionNotAllowed — unsigned binary"
            default:     meaning = "see the Security framework error above"
            }
            print("[MessageKeyStore] ❌ could not create the Enclave key pair "
                  + "(\(code)): \(meaning)")
        }
        // Keep the public half where nothing has to authenticate to read it.
        if let created, let pub = SecKeyCopyPublicKey(created) {
            storePublicKey(pub, for: profileID)
            // Record WHICH scheme made this key. Without it, an ACL refusal is
            // unattributable: a key that predates `.privateKeyUsage` and a key
            // that has it fail identically, and only one of the two is worth
            // regenerating. See `unwrap`.
            writeItem(Data([UInt8(currentKeyScheme)]), account: schemeAccount(profileID))
        }
        return created
    }

    private static func writeItem(_ data: Data, account: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ] as CFDictionary)
        SecItemAdd([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            // Readable after first unlock so a push-woken background write works.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ] as CFDictionary, nil)
    }

    private static func readItem(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let legacyStatus = BiometricAudit.measure("SecItemCopyMatching",
                                                  item: "message-key store item",
                                                  expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, &result)
        }
        guard legacyStatus == errSecSuccess else { return nil }
        return result as? Data
    }
}

/// Drives the one unlock prompt, and lets SwiftUI know when it has happened.
///
/// `Message.content` is synchronous and cannot authenticate; `evaluatePolicy` is
/// async and must not run from a view body. This sits between them: a message
/// surface asks to unlock when it appears, rows render as locked until it
/// resolves, and `isUnlocked` flipping re-renders them decrypted.
///
/// One prompt covers every row on every screen until the app is backgrounded or
/// the profile changes — both of which call `MessageKeyStore.clearCache()`, so
/// the authentication can never outlive a trip away from the app.
@MainActor
final class MessageKeyGate: ObservableObject {
    static let shared = MessageKeyGate()

    @Published private(set) var isUnlocked = false
    /// Set once the user has declined, so appearing views stop re-asking. A
    /// pull-to-refresh or a fresh foreground clears it by calling `unlock` again
    /// with `retry: true`.
    @Published private(set) var wasDeclined = false
    private var inFlight = false

    private init() {}

    /// Ask once. Concurrent callers (a list and a thread both appearing) share
    /// the single prompt rather than queueing two.
    func unlock(reason: String = "Read your messages", retry: Bool = false) async {
        if retry { wasDeclined = false }
        guard !isUnlocked, !inFlight, !wasDeclined else { return }
        inFlight = true
        defer { inFlight = false }

        // An interrupted attempt is retried, briefly and a bounded number of
        // times. At launch the sign-in prompt and this one are raised together,
        // iOS grants the hardware to one, and this one comes back
        // "Authentication canceled" — a collision, not an answer. Waiting for
        // the other prompt to finish and asking once more is the whole fix.
        //
        // Only the USER saying no stops us. Latching a collision as a refusal
        // left every row locked for a decision nobody made.
        for attempt in 0..<Self.maxInterruptedRetries {
            // Stop the moment this task is torn down. SwiftUI cancels a `.task`
            // when its view rebuilds, and the retry loop must not keep asking on
            // behalf of a screen that is gone — nor burn its attempts doing it.
            if Task.isCancelled { return }

            // The app must be able to show a sheet before we ask for one.
            guard await Self.waitUntilAppIsActive(timeout: Self.waitForActive),
                  !Task.isCancelled else { return }

            // Never raise a prompt beside one already on screen: iOS cancels one
            // of the two, and the cancelled one is us. Waiting also means the
            // user is not asked to authenticate twice in a row for two things.
            guard await BiometricCoordinator.waitUntilFree(timeout: Self.waitForOtherPrompt),
                  !Task.isCancelled else { return }

            if attempt > 0 {
                // Backoff, not a fixed beat: the wait has to outlast a person
                // answering the other prompt.
                //
                // NOT `try?`. Task.sleep throws immediately once the task is
                // cancelled, so swallowing that collapsed the whole backoff into
                // a tight loop — five attempts and five prompts in the time one
                // was meant to take.
                let delay = Self.retryBaseNanoseconds << UInt64(attempt - 1)
                do { try await Task.sleep(nanoseconds: min(delay, Self.retryCapNanoseconds)) }
                catch { return }
            }
            switch await MessageKeyStore.authenticateForReading(reason: reason) {
            case .granted:
                isUnlocked = true
                wasDeclined = false
                return
            case .refused:
                isUnlocked = false
                wasDeclined = true
                return
            case .interrupted:
                continue
            }
        }
        // Still interrupted. Leave `wasDeclined` clear so the next screen that
        // appears — or the next foreground — asks again.
        isUnlocked = false
    }

    /// Whether the app can present an authentication sheet at all.
    ///
    /// LocalAuthentication will not put UI on screen for an app that is not
    /// active, and says so as `LAError.notInteractive` — "User interaction
    /// required." At a cold launch with an existing account everything happens
    /// at once, while the scene is still coming up, and every evaluation is
    /// refused before the user could possibly see it. A fresh account did not
    /// show this only because creating a profile takes seconds of typing, by
    /// which time the app is plainly active.
    private static func waitUntilAppIsActive(timeout: TimeInterval) async -> Bool {
        #if canImport(UIKit)
        let deadline = Date().addingTimeInterval(timeout)
        while await UIApplication.shared.applicationState != .active {
            if Date() >= deadline { return false }
            do { try await Task.sleep(nanoseconds: 150_000_000) } catch { return false }
        }
        #endif
        return true
    }

    /// Enough to outlast a colliding sign-in prompt AND the time a person takes
    /// to answer it, few enough that a device which cannot authenticate is not
    /// asked forever. 1s, 2s, 4s, 8s, 8s… ≈ 30s of patience.
    private static let maxInterruptedRetries = 6
    private static let retryBaseNanoseconds: UInt64 = 1_000_000_000
    private static let retryCapNanoseconds: UInt64 = 8_000_000_000
    /// How long to stand aside for a synchronous prompt already on screen.
    private static let waitForOtherPrompt: TimeInterval = 30
    /// How long to wait for the scene to finish coming up.
    private static let waitForActive: TimeInterval = 15

    /// Called wherever the store's caches are dropped, so the UI locks with it.
    func lock() {
        isUnlocked = false
        wasDeclined = false
    }
}
