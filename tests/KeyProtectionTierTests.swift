import Foundation
import Security
import LocalAuthentication

// Covers the two halves of the -25293 fix that can be checked without a device:
// the capability→tier mapping, and the tier→(ACL flag, LAPolicy, marker) mapping.
//
// These are small, pure, and boring, which is exactly why they are here. Both of
// this app's Keychain incidents (APP-2, and the ladder e22ecd7 removed) were
// mapping mistakes, not cryptography mistakes — a gate silently becoming a
// different gate, or a policy asking for something the key would not accept.
// Nothing in the app fails loudly when those drift; a `.devicePasscode` key
// authenticated `WithBiometrics` just never opens.

print("Capability → tier")

// The one that must never regress. A biometry lockout is TRANSIENT: the user
// walks out of it by unlocking their device with the passcode. If it ever maps
// to a tier, someone with Face ID enrolled and working gets a permanently
// downgraded key for being briefly locked out.
check(DeviceAuthCapability.biometryLockout.tier == nil,
      "a biometry lockout yields no tier — it is not a reason to downgrade")
check(DeviceAuthCapability.biometryLockout.isTransient,
      "a biometry lockout is reported as recoverable")
check(DeviceAuthCapability.none.tier == nil,
      "no passcode yields no tier — nothing can protect a key")
check(DeviceAuthCapability.biometrics.tier == .biometryCurrentSet,
      "enrolled biometrics yield the strong tier")
check(DeviceAuthCapability.passcodeOnly.tier == .userPresence,
      "a passcode-only device yields the reduced tier")
check(DeviceAuthCapability.biometryDenied.tier == .userPresence,
      "an app denied biometrics yields the reduced tier")

// Capability is the CEILING; preference picks at or below it. Only a device
// with working biometrics has anything to step down from — everywhere else
// there is no choice to offer, and offering one would be a lie.
check(DeviceAuthCapability.biometrics.offersWeakerAlternative,
      "a biometric device offers the weaker alternative as a choice")
for capability in [DeviceAuthCapability.passcodeOnly, .biometryDenied, .biometryLockout, .none] {
    check(!capability.offersWeakerAlternative,
          "\(capability) offers no step down — there is nothing below it")
}

// The distinction the first version of this code got wrong, and the reason a
// user was going to be told their account was destroyed by a Settings toggle.
// `.biometryCurrentSet` is bound to the ENROLMENT: losing the enrolment takes
// the key, being unable to USE biometrics does not.
check(DeviceAuthCapability.passcodeOnly.invalidatesBiometricKeys,
      "losing the enrolment invalidates a tier-2 key")
check(DeviceAuthCapability.none.invalidatesBiometricKeys,
      "losing the passcode invalidates a tier-2 key")
check(!DeviceAuthCapability.biometryDenied.invalidatesBiometricKeys,
      "revoking the app's biometric permission does NOT invalidate a tier-2 key")
check(!DeviceAuthCapability.biometryLockout.invalidatesBiometricKeys,
      "a lockout does NOT invalidate a tier-2 key")
check(!DeviceAuthCapability.biometrics.invalidatesBiometricKeys,
      "working biometrics invalidate nothing")

// A voluntary downgrade must still be a downgrade: tier 1 sits strictly below
// tier 2, which is what `createProfile`'s ceiling check compares.
check(KeyProtectionTier.userPresence.rawValue < KeyProtectionTier.biometryCurrentSet.rawValue,
      "the reduced tier orders below the strong one")

// Every refusable state has to be able to say what is wrong AND what to do. An
// empty remedy is how a user ends up with a status code again.
for capability in [DeviceAuthCapability.biometryLockout, .passcodeOnly, .biometryDenied, .none] {
    check(!capability.headline.isEmpty && !capability.remedy.isEmpty,
          "\(capability) states both a headline and a remedy")
    check(!capability.headline.contains("-25") && !capability.remedy.contains("-25"),
          "\(capability) says nothing about an OSStatus")
}

print("")
print("Tier → policy")

// The pairing the whole design rests on. `.deviceOwnerAuthentication` against a
// `.biometryCurrentSet` key is an unlock the user completes while every row
// stays locked (e22ecd7); WithBiometrics against a `.devicePasscode` key on a
// device with no enrolment cannot even be evaluated. The policy has to ask for
// what the key needs, in both directions.
check(KeyProtectionTier.biometryCurrentSet.policy == .deviceOwnerAuthenticationWithBiometrics,
      "the strong tier authenticates with biometrics")
check(KeyProtectionTier.userPresence.policy == .deviceOwnerAuthentication,
      "the reduced tier authenticates with device-owner auth")

// The pairing that makes ONE unlock possible on every device. `.userPresence`
// accepts exactly what `.deviceOwnerAuthentication` produces — biometry or
// passcode, whichever the device has. `.devicePasscode` did not: on a biometric
// device that policy leads with Face ID, and the resulting context either made
// the choice cosmetic or was refused by the key with nothing on screen. Matching
// these by construction is what removed the fork rather than deferring it.
check(KeyProtectionTier.userPresence.accessControlFlag == .userPresence
      && KeyProtectionTier.userPresence.policy == .deviceOwnerAuthentication,
      "the reduced tier's ACL and policy are the matching pair")
check(KeyProtectionTier.userPresence.isReduced && !KeyProtectionTier.biometryCurrentSet.isReduced,
      "only the passcode tier reports itself as reduced")

// Tier 1 is the convenient mode, not just the weak one. Prompting per use on a
// passcode-gated key buys nothing — the passcode that opens it once opens it
// every time — so it would be pure friction charged against the tier that was
// chosen to avoid friction.
check(KeyProtectionTier.userPresence.holdsKeyForSession,
      "the reduced tier holds its key for the foreground session")
check(!KeyProtectionTier.biometryCurrentSet.holdsKeyForSession,
      "the strong tier re-reads, and re-prompts, per use unless Fast unlock says otherwise")

print("")
print("Tier → access control")

// Both ACLs must be constructible. A tier whose ACL cannot be built is a tier
// that throws at creation time — which is the bug this change exists to remove,
// reintroduced one level down.
for tier in [KeyProtectionTier.biometryCurrentSet, .userPresence] {
    var error: Unmanaged<CFError>?
    let acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        tier.accessControlFlag,
        &error
    )
    check(acl != nil, "tier \(tier.rawValue) builds an access control")
    error?.release()
}

// NOT an OR of the two. That combination is what Semgrep keychain-passcode-
// fallback catches and what e22ecd7 removed: it hands an attacker who knows the
// passcode a route around the flag that exists to stop them. The tiers are
// alternatives, never a union.
check(KeyProtectionTier.userPresence.accessControlFlag == .userPresence,
      "the reduced tier is exactly one flag, not a union")
check(KeyProtectionTier.biometryCurrentSet.accessControlFlag == .biometryCurrentSet,
      "the strong tier is exactly one flag, not a union")

print("")
print("Marker")

let probeID = "tier-probe-\(UUID().uuidString)"

// The default is load-bearing. Every profile created before tiers existed has no
// marker and was written under `.biometryCurrentSet`; defaulting the other way
// would authenticate all of them with a policy their keys refuse, and would
// report them in Settings as downgraded when they are not.
check(KeyProtectionTier.stored(for: probeID) == .biometryCurrentSet,
      "an absent marker reads as the strong tier")

KeyProtectionTier.storeMarker(.userPresence, for: probeID)
if KeyProtectionTier.stored(for: probeID) == .userPresence {
    check(true, "a stored marker reads back")
    KeyProtectionTier.storeMarker(.biometryCurrentSet, for: probeID)
    check(KeyProtectionTier.stored(for: probeID) == .biometryCurrentSet,
          "a marker can be overwritten")
    KeyProtectionTier.deleteMarker(for: probeID)
    check(KeyProtectionTier.stored(for: probeID) == .biometryCurrentSet,
          "a deleted marker falls back to the strong tier")
} else {
    // An unsigned CLI binary has no keychain access group, so the WRITE is
    // refused (-34018) while the read above still works. Same reason
    // MessageAtRestTests cannot reach the Secure Enclave here — see MAS-9.
    skip("a stored marker reads back", because: "no keychain access group in an unsigned binary")
    skip("a marker can be overwritten", because: "no keychain access group in an unsigned binary")
    skip("a deleted marker falls back to the strong tier", because: "no keychain access group in an unsigned binary")
    KeyProtectionTier.deleteMarker(for: probeID)
}

finish()
