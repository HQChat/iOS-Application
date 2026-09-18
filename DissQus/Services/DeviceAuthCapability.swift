//
//  DeviceAuthCapability.swift
//  DissQus
//
//  Two questions this app kept failing to ask: what can this device actually
//  gate a key behind, and which gate was THIS profile's key written under.
//
//  Not asking the first one is what produced the bug this file exists for. Both
//  key ACLs were `.biometryCurrentSet` with no passcode arm, and the Keychain
//  refuses to CREATE an item whose access control nothing on the device can ever
//  satisfy — `errSecAuthFailed`, -25293. On an iPad with no enrolled biometrics
//  that arrived as "Failed to store secret key in Keychain (status: -25293)" on
//  the first-run screen, after a handle had been typed and an HQC keypair
//  generated, with no way forward. The failure was documented (MAS-10) as "cannot
//  OPEN the key"; it is in fact "cannot create one", which makes the app
//  unusable rather than degraded.
//
//  Not asking the second one is the older mistake, and the more dangerous. APP-2
//  and commit e22ecd7 both came from a silent LADDER: try one flag, settle for a
//  weaker one, carry on. Which gate you actually got depended on the device, and
//  nothing recorded it — so nobody could answer "what is protecting my key"
//  including the code. This file exists so a downgrade is a decision with a name,
//  a user's consent behind it, and a marker on disk, rather than a fallback.
//

import Foundation
import Security
import LocalAuthentication

// MARK: - What the device can do

/// What this device can gate a key behind, asked fresh each time.
///
/// Deliberately four cases and not a boolean. The two failure modes are not the
/// same kind of thing: `.biometryLockout` is a state the user walks out of by
/// unlocking their device, and collapsing it into `.passcodeOnly` would let a
/// temporary lockout permanently downgrade the key of someone who has Face ID
/// enrolled and working.
enum DeviceAuthCapability: Equatable {
    /// Face ID / Touch ID enrolled and usable. Full protection.
    case biometrics
    /// Enrolled, but the OS has stopped accepting biometry until the device is
    /// unlocked with its passcode. TRANSIENT — never a reason to downgrade.
    case biometryLockout
    /// A passcode is set, but no biometrics are enrolled. A key can be stored
    /// here, behind a weaker gate, and only with the user's explicit consent.
    case passcodeOnly
    /// Biometrics exist on the device but THIS app cannot use them — the user
    /// turned its Face ID permission off in Settings, or there is no biometric
    /// hardware at all. Both arrive as the same `LAError`, and for this app they
    /// mean the same thing.
    ///
    /// Separate from `.passcodeOnly` for one reason, and it is the important
    /// one: **an existing key is untouched here.** `.biometryCurrentSet` is
    /// invalidated by the ENROLMENT changing, and revoking an app's permission
    /// changes no enrolment. Collapsing this into `.passcodeOnly` made
    /// `readFailureReason` tell someone their account was permanently destroyed
    /// when flipping a toggle back would have opened it.
    case biometryDenied
    /// No passcode at all. Nothing on this device can protect a key, and this
    /// app will not store one unprotected.
    case none

    /// Ask the device.
    ///
    /// A FRESH `LAContext` per probe. `canEvaluatePolicy` caches its answer on
    /// the context it was asked of, so reusing one means the second question can
    /// be answered from the first question's state instead of from the device.
    static var current: DeviceAuthCapability {
        var biometricError: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                         error: &biometricError) {
            return .biometrics
        }

        // Both of these are read BEFORE the passcode probe, because a device in
        // either state answers YES to `.deviceOwnerAuthentication` — the passcode
        // still works. Reading that as "no biometrics on this device" is exactly
        // the misread that would downgrade, or condemn, an enrolled user's key.
        if let error = biometricError, error.domain == LAErrorDomain {
            switch error.code {
            case LAError.biometryLockout.rawValue:
                return .biometryLockout
            case LAError.biometryNotAvailable.rawValue:
                // The OS gives one code for "this app's Face ID permission is
                // off" and "there is no biometric hardware". It does not matter
                // which: neither is an enrolment change, so neither destroys an
                // existing key, and that is the only distinction this app acts
                // on. A device with no passcode either has nothing to fall back
                // to at all.
                return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
                    ? .biometryDenied : .none
            default:
                break
            }
        }

        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
            return .passcodeOnly
        }

        return .none
    }

    /// Whether reaching this state has destroyed any `.biometryCurrentSet` key
    /// that was already on the device.
    ///
    /// The question `readFailureReason` has to answer, and the one the code got
    /// wrong: the flag is bound to the biometric ENROLMENT, so losing the
    /// enrolment (`.passcodeOnly`) or the passcode that anchors it (`.none`)
    /// takes the key with it, while merely being unable to USE biometrics
    /// (`.biometryDenied`, `.biometryLockout`) leaves it exactly where it was.
    /// One of those is an account that is gone; the other is a toggle.
    var invalidatesBiometricKeys: Bool {
        switch self {
        case .passcodeOnly, .none: return true
        case .biometrics, .biometryDenied, .biometryLockout: return false
        }
    }

    /// The tier a key created right now would be written under, or nil if no key
    /// can be written at all.
    var tier: KeyProtectionTier? {
        switch self {
        case .biometrics: return .biometryCurrentSet
        case .passcodeOnly, .biometryDenied: return .userPresence
        case .biometryLockout, .none: return nil
        }
    }

    /// Whether the user could ALSO choose a weaker tier than `tier` here.
    ///
    /// Only true where biometrics are actually usable — everywhere else there is
    /// nothing to step down from. This is preference, not capability, and the
    /// two are deliberately separate: a device that CAN do Face ID and a person
    /// who WANTS to use it are different facts, and the first was standing in
    /// for the second.
    var offersWeakerAlternative: Bool { self == .biometrics }


    /// Whether this state resolves on its own once the user does something
    /// ordinary. Governs whether the UI says "try again" or refuses.
    var isTransient: Bool { self == .biometryLockout }

    /// One sentence naming what is wrong. Never an OSStatus — a status code in
    /// front of a user is the bug this file was written for.
    var headline: String {
        switch self {
        case .biometrics:
            return "Face ID or Touch ID is ready."
        case .biometryLockout:
            return "Biometrics are locked."
        case .passcodeOnly:
            return "No Face ID or Touch ID is set up on this device."
        case .biometryDenied:
            return "hqchat is not allowed to use Face ID or Touch ID."
        case .none:
            return "This device has no passcode."
        }
    }

    /// What the user can do about it.
    var remedy: String {
        switch self {
        case .biometrics:
            return ""
        case .biometryLockout:
            return "Lock this device and unlock it with your passcode, then come back."
        case .passcodeOnly:
            return "Set up Face ID or Touch ID in Settings for full protection, or continue with passcode-only protection."
        case .biometryDenied:
            return "Turn Face ID back on for hqchat in Settings for full protection, or continue with passcode-only protection. Existing profiles are not affected — they open again as soon as it is back on."
        case .none:
            return "Set a passcode in Settings. Your keys cannot be protected without one."
        }
    }
}

// MARK: - Which gate a key was written under

/// The access control a stored key actually carries.
///
/// Integer-valued and persisted, mirroring `MessageKeyStore.currentKeyScheme`:
/// the lesson from both of this app's Keychain incidents is that the gate has to
/// be RECORDED, not inferred later from the device's present state — which is
/// not the state the key was written in.
enum KeyProtectionTier: Int {
    /// The unsafe-but-convenient mode, available on every device that can
    /// authenticate its owner at all. One unlock per foreground session — Face
    /// ID where there is Face ID, the passcode where there is not — and the key
    /// is then held in memory until the app backgrounds.
    ///
    /// `.userPresence` rather than `.devicePasscode`, and the reason is the
    /// whole design: `.devicePasscode` cannot be reliably satisfied by the policy
    /// this app has to authenticate with on a biometric device, so the single
    /// unlock either presented Face ID anyway (making the choice cosmetic) or
    /// handed back a context the key refused (locking the rows with nothing on
    /// screen to explain it). `.userPresence` and `.deviceOwnerAuthentication`
    /// match by construction, on every device, so there is no fork to resolve.
    ///
    /// NOT the ladder APP-2 refused. That was flags tried in SEQUENCE with
    /// nothing recording which one you ended up on. This is one flag, chosen
    /// once, written to a marker, and shown in Settings.
    ///
    /// The cost, stated plainly: this does not resist coercion. `.devicePasscode`
    /// could not be opened by presenting a face; this can.
    case userPresence = 1
    /// The default and the strong one. Bound to the biometric enrolment that
    /// existed when the key was written, so learning the passcode is not enough
    /// and re-enrolling destroys the key.
    case biometryCurrentSet = 2
}

extension KeyProtectionTier {
    /// The flag to hand `SecAccessControlCreateWithFlags`.
    var accessControlFlag: SecAccessControlCreateFlags {
        switch self {
        // nosemgrep: swift.keychain.keychain-passcode-fallback
        //
        // The rule is right about the pattern it is looking for and this is not
        // that pattern. What it catches is a weaker arm OR'd into a biometric
        // ACL — `[.biometryCurrentSet, .devicePasscode]` — which hands the
        // attacker `.biometryCurrentSet` exists to stop (someone who knows the
        // passcode, enrolling their own face) a direct route around it, leaving
        // the flag protecting almost nothing. That is why e22ecd7 removed it.
        //
        // These are two SEPARATE ACLs, never OR'd. A key is one or the other, the
        // choice is made once from `DeviceAuthCapability.current`, the weaker one
        // is shown with what it costs before it can be picked, and the answer is
        // written to a marker and displayed in Settings → Security. The
        // alternative it replaces is not a stronger key: it is no key, no
        // account, and -25293 on the welcome screen.
        case .userPresence: return .userPresence
        case .biometryCurrentSet: return .biometryCurrentSet
        }
    }

    /// The `LAPolicy` that produces a context this tier's key will accept.
    ///
    /// These must not drift apart. `.deviceOwnerAuthentication` against a
    /// `.biometryCurrentSet` key is the trap e22ecd7 fixed in the other
    /// direction: the user completes a passcode unlock, the Keychain refuses the
    /// resulting context, and the rows stay locked with nothing on screen to
    /// explain it. The policy has to ask for what the key needs.
    var policy: LAPolicy {
        switch self {
        case .userPresence: return .deviceOwnerAuthentication
        case .biometryCurrentSet: return .deviceOwnerAuthenticationWithBiometrics
        }
    }

    /// Whether this is the reduced-protection tier — the one the UI must show.
    var isReduced: Bool { self == .userPresence }

    /// Whether one unlock covers the whole foreground session.
    ///
    /// Tier 1 IS the convenient mode, not merely a weaker gate that happens to
    /// prompt as often as the strong one. Asking for a passcode on every key use
    /// would be the worst of both: more friction than Face ID and less
    /// protection. So the trade is honest and in one place — a weaker gate, one
    /// unlock, key held in memory while the app is open.
    ///
    /// Bounded by the same thing that bounds `AuthPrefs.unsecureKeyHold`:
    /// `clearCachedKey()` on background and on profile switch, on both
    /// platforms. It is a foreground-session hold, never a persistent one.
    var holdsKeyForSession: Bool { isReduced }

    /// Settings-facing description of what is actually holding the key.
    var detail: String {
        switch self {
        case .userPresence:
            return "Quick unlock · one unlock per launch, then held in memory while the app is open"
        case .biometryCurrentSet:
            return "Secure Enclave / Keychain, biometric-gated"
        }
    }

    // MARK: Marker

    /// Its own service, not the profile key's: this is metadata about a key, and
    /// it has to be readable by callers that never touch the key itself —
    /// `MessageKeyStore` is not a `ProfileManager` client and still has to know
    /// which policy to authenticate with.
    static let markerService = "com.dissqus.keyprotection"

    /// Reading this grants nothing. The marker says which ACL the key carries; it
    /// is not the ACL, and the Keychain does not consult it. Flipping it to the
    /// weaker value does not weaken the key — it only makes this app authenticate
    /// with a policy that key will refuse, which fails closed.
    static func stored(for profileId: String) -> KeyProtectionTier {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: markerService,
            kSecAttrAccount as String: profileId,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let raw = (result as? Data)?.first,
              let tier = KeyProtectionTier(rawValue: Int(raw)) else {
            // No marker means a profile created before tiers existed, and every
            // one of those was written under `.biometryCurrentSet`. The default
            // has to be the STRONG one: defaulting to the weak tier would make
            // the app authenticate every legacy profile with a policy its key
            // refuses, and would misreport them in Settings as downgraded.
            return .biometryCurrentSet
        }
        return tier
    }

    static func storeMarker(_ tier: KeyProtectionTier, for profileId: String) {
        deleteMarker(for: profileId)
        SecItemAdd([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: markerService,
            kSecAttrAccount as String: profileId,
            kSecValueData as String: Data([UInt8(tier.rawValue)]),
            // AfterFirstUnlock: a push-woken background receive may need to know
            // the tier before anyone has unlocked the device this boot.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ] as CFDictionary, nil)
    }

    static func deleteMarker(for profileId: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: markerService,
            kSecAttrAccount as String: profileId
        ] as CFDictionary)
    }
}
