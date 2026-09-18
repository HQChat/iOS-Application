// The authenticated context shared between the two key stores.
//
// WHY THIS EXISTS. A tier-1 profile is the CONVENIENT tier, and its defining
// property is one unlock per foreground session across BOTH key stores —
// `ProfileManager` opens the identity key, `MessageKeyStore` opens the message
// keys, and whichever asks first publishes its `LAContext` for the other to
// adopt. Prompting per use there would add friction without protection: what
// opens the key once opens it every time.
//
// That is three pieces of interacting mutable state — who prompted, what was
// published, what was discarded — reached from two call sites, and two commits
// in #133 exist because it went wrong (`186390e`, "One prompt means one prompt:
// stop the two auth sheets racing each other"). `KeyProtectionTierTests` covers
// the tier MAPPING. Nothing covered this.
//
// No Keychain and no biometrics here: every property below is about the sharing
// protocol, which is ordinary state behind a lock. What a context can actually
// open needs a signed build on real hardware — see MAS-9.

import Foundation
import LocalAuthentication

// `Friend.swift` needs these and their real home, IdentityManager.swift, is not
// in this slice — pulling it in would drag the whole identity stack along for an
// extension of four lines. MessageAtRestTests.swift carries the same pair for
// the same reason. Safe to duplicate only because no file in THIS slice declares
// it too; ConversationEnvelopeV3.swift warns about exactly that collision.
extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var out = Data(capacity: hexString.count / 2)
        var i = hexString.startIndex
        while i < hexString.endIndex {
            let j = hexString.index(i, offsetBy: 2)
            guard let b = UInt8(hexString[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        self = out
    }
}

print("Shared authenticated context")

// Each test starts from a known state. `discardAuthenticatedContext` is the only
// public way to clear it, which is itself worth asserting.
MessageKeyStore.discardAuthenticatedContext()
check(MessageKeyStore.sharedAuthenticatedContext() == nil,
      "discard leaves nothing to share")
check(!MessageKeyStore.canRead, "…and canRead agrees")

// MARK: - Adoption

let first = LAContext()
MessageKeyStore.adoptAuthenticatedContext(first)
check(MessageKeyStore.sharedAuthenticatedContext() === first,
      "an adopted context is the one handed back")
check(MessageKeyStore.canRead, "…and canRead agrees")

// THE PROPERTY THE RACING SHEETS BROKE. A second adopter must not replace the
// first: two stores that each published their own context would each have
// prompted, which is the two prompts this design exists to avoid.
let second = LAContext()
MessageKeyStore.adoptAuthenticatedContext(second)
check(MessageKeyStore.sharedAuthenticatedContext() === first,
      "a second adoption does not displace the first")

// MARK: - Discard and retry
//
// A published context that turns out not to open a key is discarded, and the
// caller authenticates properly. The worst case is the two prompts this used to
// cost — never a lockout, which is what leaving a broken context in place would
// produce.

MessageKeyStore.discardAuthenticatedContext()
check(MessageKeyStore.sharedAuthenticatedContext() == nil,
      "a context that did not work is dropped")
check(!MessageKeyStore.canRead, "…and reads stop claiming they can succeed")

let third = LAContext()
MessageKeyStore.adoptAuthenticatedContext(third)
check(MessageKeyStore.sharedAuthenticatedContext() === third,
      "…and a fresh one can then be adopted — a discard is not a lockout")

// MARK: - Concurrency
//
// The two stores are called from different places and there is no ordering
// between them. Whichever arrives first must win, and every later reader must
// see that same one.
//
// WHAT THIS DOES AND DOES NOT CATCH, measured rather than assumed. Making
// `adopt` replace unconditionally — the racing-sheets bug itself — fails the
// displacement check above every time. But splitting the lock so the nil-check
// and the write are no longer atomic, which is the OTHER way two contexts could
// each look "first", was injected and NOT caught: 32 contenders on a fast
// machine do not reliably interleave in a window that narrow.
//
// So this section is evidence that the protocol holds under concurrent use, not
// proof that it is free of a check-then-act race. Catching that class properly
// needs the gap widened deliberately or a tool that reasons about
// interleavings — neither of which a plain suite does. Said here because a
// concurrency test that passes is the easiest kind of test to over-read.

MessageKeyStore.discardAuthenticatedContext()

let contexts = (0..<32).map { _ in LAContext() }
let group = DispatchGroup()
for c in contexts {
    DispatchQueue.global().async(group: group) {
        MessageKeyStore.adoptAuthenticatedContext(c)
    }
}
group.wait()

let winner = MessageKeyStore.sharedAuthenticatedContext()
check(winner != nil, "a concurrent scramble still settles on a context")
check(contexts.contains(where: { $0 === winner }),
      "…and it is one of the contexts that was actually offered")

// Every reader sees the same one. If adoption were not atomic this could differ
// between calls even after the scramble settled.
var stable = true
for _ in 0..<200 where MessageKeyStore.sharedAuthenticatedContext() !== winner { stable = false }
check(stable, "…and every reader afterwards sees that same one")

// Readers running while adopters are still arriving must never see a torn state:
// either nil or a real context, never a half-published one.
MessageKeyStore.discardAuthenticatedContext()
let mixed = DispatchGroup()
var sawSomethingOdd = false
let oddLock = NSLock()
for i in 0..<64 {
    DispatchQueue.global().async(group: mixed) {
        if i % 2 == 0 {
            MessageKeyStore.adoptAuthenticatedContext(LAContext())
        } else {
            let c = MessageKeyStore.sharedAuthenticatedContext()
            let readable = MessageKeyStore.canRead
            // canRead is defined as "a context exists and we are not locked
            // out", so a non-nil context with canRead false would mean the two
            // reads disagreed mid-update.
            if c != nil && !readable {
                oddLock.lock(); sawSomethingOdd = true; oddLock.unlock()
            }
        }
    }
}
mixed.wait()
check(!sawSomethingOdd, "a reader never catches the context half-published")

MessageKeyStore.discardAuthenticatedContext()

// ── The tier a profile authenticates against ─────────────────────────────────
//
// `activeTier` decides which LAPolicy the unlock runs, and its default is the
// one that matters: a profile written before tiers existed carries no marker, so
// nil must read as the STRONGEST tier. Defaulting the other way would silently
// downgrade every pre-existing profile to whatever the weaker policy accepts —
// a change nobody would see, because the unlock would still succeed.

MessageKeyStore.setActiveProfile(nil)
check(!MessageKeyStore.canRead, "no profile means nothing is readable")

// An unlock asked for with NO PROFILE must be refused without prompting.
// `MessageKeyGate.unlock()` runs from the scene handler on every `.active`,
// which includes sitting on the welcome screen before any profile exists — and
// the user got a Face ID prompt for an empty database. On the creation path it
// landed in the middle of the consent prompt, which is one half of "two codes
// are prompted".
let refusedWithoutProfile = await MessageKeyStore.authenticateForReading(reason: "test")
check(refusedWithoutProfile == .refused,
      "an unlock with no profile is refused, not prompted — got \(refusedWithoutProfile)")
check(MessageKeyStore.sharedAuthenticatedContext() == nil,
      "…and nothing was published for the next reader to adopt")

// Setting and clearing the active profile is visible to the next read.
let someProfile = UUID()
MessageKeyStore.setActiveProfile(someProfile)
check(MessageKeyStore.sharedAuthenticatedContext() == nil,
      "a fresh profile starts with no authenticated context")
MessageKeyStore.setActiveProfile(nil)
check((await MessageKeyStore.authenticateForReading(reason: "test")) == .refused,
      "clearing the profile refuses again rather than reusing the last one")

finish()