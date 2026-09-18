import Foundation
import CryptoKit

/// The target: `RatchetSession.open` against attacker-chosen `n` and `pn`.
///
/// WHY THIS SURFACE. `n` and `pn` arrive on a frame header and are read to CHOOSE
/// the message key — so they cannot have been authenticated by the payload that
/// key opens. Everything the receiver does with them happens *before* the AEAD
/// tag is checked, on the MainActor, on a value the sender picked. That is the
/// definition of an unauthenticated input, and the last unbuilt target in this
/// directory's own ladder: "what does a frame claiming n = 1_999_999 cost?"
///
/// FOUR ORACLES:
///
///   A. IT RETURNS, AND RETURNS FAST. Swift traps on Int overflow, so
///      `header.pn - 1` and `header.pn - current.n` are crash candidates for
///      extreme values. And `walkChain` is an HKDF per step: if a gap is walked
///      before it is bounded, n = 2^31 is two billion invocations and the app is
///      gone. `DoubleRatchet.walkChain` bounds BEFORE walking, and a WATCHDOG
///      enforces that — an elapsed-time check placed after the call cannot catch
///      a call that never returns. See the note on `Watchdog`.
///
///   B. THE CACHE STAYS BOUNDED. `state.skipped` is persisted into the Keychain
///      on every save, so an unbounded cache is not just memory — it is a write
///      that grows without limit. `maxSkipped` is 2000 and nothing may exceed it,
///      whatever sequence of frames arrives.
///
///   C. A REFUSED FRAME CHANGES NOTHING. `open` is documented to commit only past
///      the `verify` gate. A frame that fails to authenticate must leave the
///      session byte-identical, or a peer who can send garbage can move the
///      receiver's state — which is the forged-step defence.
///
///   D. A REPLAY OF A CONSUMED POSITION YIELDS NOTHING, even when the verifier
///      would have said yes. `n < current.n` is refused before the payload is
///      consulted.
///
/// WHICH ORACLES ARE VALIDATED, and which are not. A target that has never been
/// shown to fail is not evidence of anything, so each oracle was tested by
/// breaking the code it guards:
///
///   A (bounded time)  VALIDATED. Removing the pre-walk bound from `walkChain`
///                     makes the watchdog abort on n = 2^32. Without the
///                     watchdog the run simply hung, which from outside is
///                     indistinguishable from a slow fuzzer — see `Watchdog`.
///
///   D (replay)        VALIDATED, but only by removing TWO guards. Deleting
///                     `header.n >= current.n` from `open` alone changes nothing
///                     observable, because `walkChain` independently refuses a
///                     backwards walk (`targetN >= fromN`). The refusal is
///                     defended twice. With both removed the oracle trips.
///
///   B (cache bound)   NOT VALIDATED, and the reason is the same shape. Removing
///                     the eviction in `cacheSkipped` does not make the cache
///                     exceed `maxSkipped`, because `walkChain` already caps how
///                     many keys a single call can produce. No single-point
///                     injection was found that breaches the bound, so this
///                     oracle is unproven rather than proven — it may be
///                     guarding something unreachable.
///
///   C (no state change on refusal)  NOT VALIDATED. No cheap injection was found
///                     that moves state without also changing the return value.
///
/// The KEM is a stub, deliberately: the real library is a native binary this
/// runner does not link, and every property above is about the state machine
/// rather than the primitive. The stub implicitly rejects — a wrong key yields a
/// pseudo-random secret rather than an error — because that is what the real
/// HQC KEM does, and a throwing stub would grant for free exactly the property
/// the forged-step defence must provide for itself.

// MARK: - Stub KEM (mirrors tests/RatchetSessionTests.swift)

enum FuzzKemError: Error { case bad }

struct FuzzStubKem: RatchetKem {
    func generateKeypair() throws -> (pk: Data, sk: Data) {
        var tag = Data(count: 32)
        _ = tag.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        return (tag, tag)
    }
    func encapsulate(_ pk: Data) throws -> (ct: Data, ss: Data) {
        var ss = Data(count: 32)
        _ = ss.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let mask = Data(SHA256.hash(data: pk))
        var body = Data(count: 32)
        for i in 0..<32 { body[i] = ss[i] ^ mask[i] }
        return (mask + body, ss)
    }
    func decapsulate(sk: Data, ct: Data) throws -> Data {
        guard ct.count == 64 else { throw FuzzKemError.bad }
        let mask = Data(SHA256.hash(data: sk))
        guard ct.prefix(32) == mask else { return Data(SHA256.hash(data: sk + ct)) }
        var ss = Data(count: 32)
        for i in 0..<32 { ss[i] = ct[32 + i] ^ mask[i] }
        return ss
    }
}

private struct FuzzPeer {
    let identity: (pk: Data, sk: Data)
    let medium: (pk: Data, sk: Data)
    let oneTime: (pk: Data, sk: Data)

    init(kem: RatchetKem) throws {
        identity = try kem.generateKeypair()
        medium = try kem.generateKeypair()
        oneTime = try kem.generateKeypair()
    }
    func bundle() -> PrekeyBundle {
        PrekeyBundle(identityPk: identity.pk, mediumPk: medium.pk,
                     oneTimePk: oneTime.pk, oneTimeId: 0)
    }
    func secrets() -> PrekeySecrets {
        PrekeySecrets(identitySk: identity.sk, mediumSk: medium.sk) { id in
            id == 0 ? oneTime.sk : nil
        }
    }
}

// MARK: - Watchdog
//
// A deadline that fires DURING the call, not after it.
//
// The obvious oracle — time the call, assert it was fast — cannot catch the bug
// it exists for. Removing the pre-walk bound from `walkChain` makes a frame
// claiming n = 2^31 spend two billion HKDF invocations inside `open`, and an
// elapsed-time check placed after `open` returns never runs, because `open`
// never returns. Verified: with the bound removed the fuzzer simply hung, which
// from the outside is indistinguishable from a slow fuzzer.
//
// So the deadline is armed before the call and disarmed after, and a background
// thread aborts the process if it expires. An abort mid-walk is exactly the
// report wanted: the stack shows where it was stuck.
//
// THE LIMIT IS DELIBERATELY ENORMOUS, and that is the lesson from getting it
// wrong. At 5 seconds this fired once on `n=2001 pn=2147483647` while a full
// Xcode simulator run was saturating the machine, and the case did not reproduce
// afterwards: the worst single `open` measured 23ms, with the skipped cache full
// and the session fully accumulated. A wall-clock watchdog measures the
// scheduler as much as the code, so a tight bound reports load as a finding.
//
// 30 seconds keeps it useful because the bug it exists for is not marginal: an
// unbounded walk at n = 2^31 is two billion HKDF invocations, which ran past ten
// MINUTES before being killed. Anything between 23ms and 30s is not the defect
// this is looking for.
private final class Watchdog {
    private let queue = DispatchQueue(label: "ratchet-watchdog")
    private var deadline: Date?
    private var what = ""
    private let lock = NSLock()

    init(limit: TimeInterval) {
        queue.async { [self] in
            while true {
                Thread.sleep(forTimeInterval: 0.25)
                lock.lock()
                let d = deadline, w = what
                lock.unlock()
                if let d, Date() > d {
                    FileHandle.standardError.write(Data(
                        "\n❌ WATCHDOG: open() exceeded \(limit)s — \(w)\n".utf8))
                    FileHandle.standardError.synchronizeFile()
                    abort()
                }
            }
        }
    }
    func arm(_ description: String, limit: TimeInterval) {
        lock.lock(); deadline = Date().addingTimeInterval(limit); what = description; lock.unlock()
    }
    func disarm() { lock.lock(); deadline = nil; lock.unlock() }
}

private let watchdog = Watchdog(limit: 30.0)

// MARK: - Reach counters
//
// Does this target actually get anywhere?
//
// A fuzzer that never reaches the state an oracle guards reports the same clean
// run as one that reaches it and finds nothing — and that is not hypothetical
// here. An earlier version of this generator produced almost only fabricated
// headers, which `open` refuses in its first few lines, so the replay oracle
// never executed and an injected defect (removing the consumed-position guard)
// went completely undetected. These counters are printed at exit so a run that
// proves nothing says so.
private final class Reach {
    var accepted = 0            // frames that opened
    var replaysRefused = 0      // consumed positions correctly refused a second time
    var cacheGrew = 0           // opens that added to the skipped cache
    var maxCache = 0
    let lock = NSLock()
    func bump(_ f: (Reach) -> Void) { lock.lock(); f(self); lock.unlock() }
}
private let reach = Reach()

private let installReport: Void = {
    atexit {
        reach.lock.lock()
        let line = "reach: accepted=\(reach.accepted) replays-refused=\(reach.replaysRefused) " +
                   "cache-grew=\(reach.cacheGrew) max-cache=\(reach.maxCache)"
        reach.lock.unlock()
        FileHandle.standardError.write(Data((line + "\n").utf8))
    }
}()

// MARK: - The target

/// Values that break arithmetic, sit on the bound, or sit just past it. A
/// uniform Int would essentially never land on any of them.
private let INTERESTING: [Int] = [
    0, 1, 2, -1, -2,
    DoubleRatchet.maxSkipped - 1, DoubleRatchet.maxSkipped, DoubleRatchet.maxSkipped + 1,
    1_999_999,                                   // the ladder's own example
    Int(Int32.max), Int(Int32.max) + 1,
    Int(UInt32.max), Int(UInt32.max) + 1,        // past what the wire format holds
    Int.max, Int.max - 1, Int.min, Int.min + 1,  // the overflow candidates
]

func fuzzRatchetState(_ input: Data) {
    _ = installReport
    guard input.count >= 4 else { return }
    var cursor = 0
    func byte() -> Int {
        defer { cursor += 1 }
        return cursor < input.count ? Int(input[input.startIndex + cursor]) : 0
    }
    /// Mostly an interesting value; sometimes a small arbitrary one, so the
    /// ordinary paths stay reachable too.
    func number() -> Int {
        let b = byte()
        return b < 200 ? INTERESTING[b % INTERESTING.count] : (byte() << 8) | byte()
    }

    let kem = FuzzStubKem()
    guard let bob = try? FuzzPeer(kem: kem),
          var alice = try? RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    else { return }

    // A real session on Bob's side, with a real first frame, so `open` is being
    // driven against ESTABLISHED state rather than a blank one — a blank session
    // refuses almost everything for uninteresting reasons.
    guard let sealed = try? RatchetSession.seal(kem: kem, state: &alice.state),
          var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                         header: alice.header)
    else { return }
    let sealedKey = sealed.key
    _ = RatchetSession.open(kem: kem, state: &bobState, header: sealed.header,
                            verify: { $0 == sealedKey })

    // REAL frames, held back rather than delivered.
    //
    // Without these the target could not reach its own accept path: a header with
    // a random cid and no step material is refused in the first few lines, so the
    // replay oracle never ran and an injected defect (removing the
    // consumed-position guard) went UNCAUGHT. Sealing a handful of genuine
    // frames and delivering them out of order, twice, or not at all is what
    // actually exercises the skipped-key cache and the replay refusal.
    var pending: [(header: RatchetHeader, key: Data)] = []
    for _ in 0..<8 {
        guard let f = try? RatchetSession.seal(kem: kem, state: &alice.state) else { break }
        pending.append((f.header, f.key))
    }

    // ORACLE C needs a before-picture that survives the call.
    func snapshot(_ s: RatchetSessionState) -> String {
        "\(s.skipped.count)|\(s.seenChains.joined(separator: ","))|" +
        "\(s.recv?.n ?? -1)|\(s.send?.n ?? -1)|\(s.prevSendN)|\(hexOf(s.root))|" +
        "\(hexOf(s.peerRkPub ?? Data()))"
    }

    let rounds = 1 + (byte() % 8)
    for _ in 0..<rounds {
        // Half the time a REAL frame (possibly out of order or repeated), half
        // the time a fabricated header. The real ones reach the accept path; the
        // fabricated ones probe the refusals.
        let useReal = !pending.isEmpty && byte() % 2 == 0
        let real = useReal ? pending[byte() % pending.count] : nil

        let header: RatchetHeader
        if let real {
            // Sometimes exactly as sealed, sometimes with the indices rewritten —
            // a real cid and real step material, pointed at an absurd position.
            header = byte() % 3 == 0
                ? real.header
                : RatchetHeader(cid: real.header.cid, rk: real.header.rk,
                                kemCt: real.header.kemCt, n: number(), pn: number())
        } else {
            header = RatchetHeader(
                cid: byte() % 3 == 0 ? sealed.header.cid : hexOf(Data([UInt8(byte())])),
                rk: byte() % 4 == 0 ? sealed.header.rk : nil,
                kemCt: byte() % 4 == 0 ? sealed.header.kemCt : nil,
                n: number(),
                pn: number()
            )
        }

        // ORACLE C: a frame that cannot authenticate must change nothing.
        let before = snapshot(bobState)
        let started = Date()
        watchdog.arm("n=\(header.n) pn=\(header.pn) cid=\(header.cid)", limit: 30.0)
        let forged = RatchetSession.open(kem: kem, state: &bobState, header: header,
                                         verify: { _ in false })
        watchdog.disarm()
        let elapsed = Date().timeIntervalSince(started)

        precondition(forged == nil, "a frame with a failing tag returned a key")
        precondition(snapshot(bobState) == before,
                     "a refused frame moved the session: n=\(header.n) pn=\(header.pn)")

        // ORACLE A: bounded time. A walk that ran before it was bounded would be
        // an HKDF per step — 2 billion of them for n = 2^31 — so a second is
        // enormously generous and still catches it.
        precondition(elapsed < 1.0,
                     "open took \(elapsed)s for n=\(header.n) pn=\(header.pn) — a gap was walked before it was bounded")

        // ORACLE B: the persisted cache stays bounded, whatever arrives.
        precondition(bobState.skipped.count <= DoubleRatchet.maxSkipped,
                     "skipped cache grew to \(bobState.skipped.count), past maxSkipped")

        // ORACLE D: the same header with a verifier that WOULD pass. Anything
        // refused here was refused before the payload was consulted, which is the
        // stronger claim — and anything accepted must still leave the cache sane.
        // The verifier models AES-GCM: a tag passes exactly when the key the
        // receiver derived is the key the sender sealed with. For a real frame
        // that is the real key — granting acceptance with `{ _ in true }` would
        // hand the state machine the very property the forged-step defence has to
        // provide for itself.
        let expected = real?.key
        watchdog.arm("optimistic n=\(header.n) pn=\(header.pn)", limit: 30.0)
        let optimistic = RatchetSession.open(kem: kem, state: &bobState, header: header,
                                             verify: { k in expected.map { $0 == k } ?? true })
        watchdog.disarm()
        precondition(bobState.skipped.count <= DoubleRatchet.maxSkipped,
                     "skipped cache grew to \(bobState.skipped.count) after an accepted frame")
        reach.bump {
            $0.maxCache = max($0.maxCache, bobState.skipped.count)
            if bobState.skipped.count > 0 { $0.cacheGrew += 1 }
            if optimistic != nil { $0.accepted += 1 }
        }

        if optimistic != nil {
            // Accepting is legal for a well-formed straggler. Replaying the very
            // same position must not be.
            let again = RatchetSession.open(kem: kem, state: &bobState, header: header,
                                            verify: { k in expected.map { $0 == k } ?? true })
            precondition(again == nil,
                         "a consumed position was delivered twice: n=\(header.n) cid=\(header.cid)")
            reach.bump { $0.replaysRefused += 1 }
        }
    }
}

private func hexOf(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
