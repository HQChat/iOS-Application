import Foundation
import CryptoKit

// The v2 KEM double ratchet state machine, end to end.
//
// Driven over a STUB KEM, not HQC: the real library is a native binary this test
// runner does not link. The stub is a real (if trivial) KEM — encapsulation
// picks a fresh secret and only the matching secret key recovers it — so every
// property here is about the ratchet, and none can pass by accident on a
// degenerate KEM.
//
// Mirrors services/server/test/ratchet-session.test.ts. The two state machines
// have to agree on behaviour, not just on KDF output, or a Swift client and the
// TS bot will disagree about which frames are deliverable.

print("RatchetSession")

func hx(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

/// Random bytes, for frames an attacker would fabricate rather than derive.
func randomData(_ count: Int) -> Data {
    var d = Data(count: count)
    _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    return d
}

/// pk is a random tag; sk is the same tag. Encapsulating produces a random
/// secret and a ciphertext carrying it XOR-masked under the tag, so
/// decapsulating with the WRONG sk throws. That is all the ratchet depends on.
struct StubKem: RatchetKem {
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
        // Length is the one thing the real wrappers do reject: HQCService throws
        // on a wrong-sized ciphertext and on nothing else.
        guard ct.count == 64 else { throw StubKemError.bad }
        let mask = Data(SHA256.hash(data: sk))
        guard ct.prefix(32) == mask else {
            // IMPLICIT REJECTION, which is what the real KEM does and what this
            // stub used to get exactly backwards. It threw here, "the way a real
            // KEM's implicit rejection would" — but an implicitly-rejecting KEM
            // does not signal failure at all: it hands back a pseudo-random key,
            // which is the entire point of the construction. While it threw,
            // this file validated the state machine against a KEM strictly
            // stronger than the one the app ships on, and granted for free the
            // property the forged-step defence has to provide for itself.
            return Data(SHA256.hash(data: sk + ct))
        }
        let body = ct.suffix(32)
        var ss = Data(count: 32)
        for i in 0..<32 { ss[i] = body[body.startIndex + i] ^ mask[i] }
        return ss
    }

    enum StubKemError: Error { case bad }
}

/// A peer with published prekeys, as the directory would serve them.
struct StubPeer {
    let identity: (pk: Data, sk: Data)
    let medium: (pk: Data, sk: Data)
    let oneTime: [(pk: Data, sk: Data)]

    init(kem: RatchetKem, oneTimeCount: Int = 1) throws {
        identity = try kem.generateKeypair()
        medium = try kem.generateKeypair()
        oneTime = try (0..<oneTimeCount).map { _ in try kem.generateKeypair() }
    }

    func bundle(_ id: Int = 0) -> PrekeyBundle {
        let ot = id < oneTime.count ? oneTime[id] : nil
        return PrekeyBundle(identityPk: identity.pk, mediumPk: medium.pk,
                            oneTimePk: ot?.pk, oneTimeId: ot == nil ? nil : id)
    }

    func secrets(spent: Bool = false) -> PrekeySecrets {
        PrekeySecrets(identitySk: identity.sk, mediumSk: medium.sk) { id in
            if spent { return nil }
            return id < oneTime.count ? oneTime[id].sk : nil
        }
    }
}

let kem = StubKem()

/// Seal a message and hand back exactly what the wire would carry.
func sendMsg(_ state: inout RatchetSessionState, at now: Date = Date()) -> (header: RatchetHeader, key: String)? {
    guard let sealed = try? RatchetSession.seal(kem: kem, state: &state, now: now) else { return nil }
    return (sealed.header, hx(sealed.key))
}

/// Open a frame the sender really sealed; returns the key the receiver derived.
///
/// The verifier stands in for AES-GCM, and it has to be MODELLED rather than
/// stubbed to `true`: a tag passes exactly when the key the receiver derived is
/// the key the sender sealed with. Since `open` commits nothing until the
/// verifier returns true, a stub that always agreed would re-open every hole
/// this file is here to guard.
func openMsg(_ state: inout RatchetSessionState,
             _ frame: (header: RatchetHeader, key: String)) -> String? {
    guard let key = RatchetSession.open(kem: kem, state: &state, header: frame.header,
                                        verify: { hx($0) == frame.key }) else { return nil }
    return hx(key)
}

/// `open` with a tag that CANNOT pass — a forged or corrupt frame.
func openForged(_ state: inout RatchetSessionState, _ header: RatchetHeader) -> String? {
    guard let key = RatchetSession.open(kem: kem, state: &state, header: header,
                                        verify: { _ in false }) else { return nil }
    return hx(key)
}

/// `open` with a tag that WOULD pass, for frames that must be refused before the
/// payload is ever consulted. The stronger form of those assertions: not "this
/// frame failed to authenticate" but "this frame never got that far".
func openAssumingValid(_ state: inout RatchetSessionState, _ header: RatchetHeader) -> String? {
    guard let key = RatchetSession.open(kem: kem, state: &state, header: header,
                                        verify: { _ in true }) else { return nil }
    return hx(key)
}

func initHeader(_ h: RatchetInitHeader) -> RatchetInitHeader { h }

// --- The initiator's first message needs no round trip --------------------
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    let first = sendMsg(&alice.state)!
    check(first.header.n == 0 && first.header.pn == 0, "the first message opens at index 0")
    check(alice.state.send != nil, "a sending chain exists before any reply")

    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)
    check(bobState != nil, "the init frame stands on its own")
    check(openMsg(&bobState!, first) == first.key,
          "the first message decrypts with no prior contact")
}

// --- A conversation ratchets on direction flips ---------------------------
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    let opening = sendMsg(&alice.state)!
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    check(openMsg(&bobState, opening) == opening.key, "B opens A's opener")

    check(RatchetSession.shouldStep(bobState), "the responder steps on its first reply")
    let reply = sendMsg(&bobState)!
    check(reply.header.rk != nil && reply.header.kemCt != nil,
          "a step advertises a key and a ciphertext")
    check(openMsg(&alice.state, reply) == reply.key, "A follows the step")

    var clock = Date()
    var stayedInSync = true
    for _ in 0..<4 {
        clock = clock.addingTimeInterval(DoubleRatchet.ratchetMinStepInterval + 1)
        let fromA = sendMsg(&alice.state, at: clock)!
        if openMsg(&bobState, fromA) != fromA.key { stayedInSync = false }

        clock = clock.addingTimeInterval(DoubleRatchet.ratchetMinStepInterval + 1)
        let fromB = sendMsg(&bobState, at: clock)!
        if openMsg(&alice.state, fromB) != fromB.key { stayedInSync = false }
    }
    check(stayedInSync, "four turns of stepping stay in sync")
    check(hx(alice.state.root) == hx(bobState.root), "both sides hold the same root")
}

// --- A rapid exchange does not step every turn ----------------------------
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    let opening = sendMsg(&alice.state)!
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    _ = openMsg(&bobState, opening)

    let clock = Date()
    let firstReply = sendMsg(&bobState, at: clock)!
    check(firstReply.header.rk != nil, "the first reply steps")
    _ = openMsg(&alice.state, firstReply)

    // Inside the rate limit and under the message cap, further messages continue
    // the chain instead of paying ~29 kB each.
    var steps = 0
    var allOpened = true
    for _ in 0..<10 {
        let f = sendMsg(&bobState, at: clock.addingTimeInterval(1))!
        if f.header.rk != nil { steps += 1 }
        if openMsg(&alice.state, f) != f.key { allOpened = false }
    }
    check(steps == 0, "no step inside the rate limit")
    check(allOpened, "…and every message still opens")

    // The per-chain cap forces one even with the clock frozen. It fires DURING a
    // long run, since sentOnChain resets on each step.
    var capSteps = 0
    let run = DoubleRatchet.ratchetMaxMessagesPerChain * 3
    for _ in 0..<run {
        let f = sendMsg(&bobState, at: clock.addingTimeInterval(1))!
        if f.header.rk != nil { capSteps += 1 }
        if openMsg(&alice.state, f) != f.key { allOpened = false }
    }
    check(capSteps >= 2, "the per-chain cap forced \(capSteps) steps over \(run) messages")
    check(allOpened, "…and the run stayed decryptable throughout")
}

// --- Out-of-order and stragglers across a step ----------------------------
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!

    // Three bare frames on Alice's opening chain, none delivered yet.
    let a0 = sendMsg(&alice.state)!
    let a1 = sendMsg(&alice.state)!
    let a2 = sendMsg(&alice.state)!
    check(a0.header.rk == nil && a2.header.rk == nil, "all bare frames")
    check(a0.header.cid == a2.header.cid, "…and all on one chain")

    // Bob replies, so Alice steps on her next send.
    let clock = Date().addingTimeInterval(DoubleRatchet.ratchetMinStepInterval + 1)
    let bobReply = sendMsg(&bobState, at: clock)!
    _ = openMsg(&alice.state, bobReply)

    let later = clock.addingTimeInterval(DoubleRatchet.ratchetMinStepInterval + 1)
    let a3 = sendMsg(&alice.state, at: later)!
    check(a3.header.rk != nil, "Alice stepped")
    check(a3.header.pn == 3, "pn reports the old chain ran to 3")

    // Bob receives the STEPPED frame first — the reordering that matters.
    check(openMsg(&bobState, a3) == a3.key, "the new chain opens")

    // The stragglers now arrive out of order, all on the retired chain. `pn` let
    // Bob drain that chain into the cache when he stepped.
    check(openMsg(&bobState, a1) == a1.key, "straggler a1 resolves")
    check(openMsg(&bobState, a0) == a0.key, "straggler a0 resolves")
    check(openMsg(&bobState, a2) == a2.key, "straggler a2 resolves")
    check(openMsg(&bobState, a1) == nil, "…and cannot be replayed")
    check(bobState.recv?.n == 1, "the live chain advanced only for a3")
}

// --- Replay and hostile input ---------------------------------------------
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    let once = sendMsg(&alice.state)!
    check(openMsg(&bobState, once) == once.key, "first delivery works")
    check(openMsg(&bobState, once) == nil, "the replay gets nothing")

    // `n` picks the key, so it is read before the payload can authenticate it.
    let liveCid = DoubleRatchet.chainId(bobState.peerRkPub!)
    let started = Date()
    let hostile = openAssumingValid(&bobState, RatchetHeader(cid: liveCid, n: 2_000_000_000, pn: 0))
    check(hostile == nil, "a hostile n is refused")
    check(Date().timeIntervalSince(started) < 0.1, "…in constant time, not by walking")

    check(openAssumingValid(&bobState, RatchetHeader(cid: liveCid, n: -1, pn: 0)) == nil, "negative n refused")
    check(openAssumingValid(&bobState, RatchetHeader(cid: liveCid, n: 0, pn: -1)) == nil, "negative pn refused")
    check(openAssumingValid(&bobState, RatchetHeader(cid: "not-hex", n: 0, pn: 0)) == nil, "bad cid refused")
    check(openAssumingValid(&bobState, RatchetHeader(cid: "", n: 0, pn: 0)) == nil, "empty cid refused")

    // The session still works afterwards — a refusal is not a teardown.
    let good = sendMsg(&alice.state)!
    check(openMsg(&bobState, good) == good.key, "the session survives hostile input")
}

// --- A step we cannot decapsulate is refused, and leaves the root alone ----
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    _ = openMsg(&bobState, sendMsg(&alice.state)!)

    let rootBefore = hx(alice.state.root)
    let stranger = try! kem.generateKeypair()
    let forged = try! kem.encapsulate(stranger.pk)  // not encapsulated to Alice
    // Note what does NOT reject this: the decapsulation. It succeeds, and hands
    // back a pseudo-random secret, because that is what implicit rejection means.
    // The tag is the only thing that can refuse it, so the tag is what does.
    let refused = openForged(&alice.state, RatchetHeader(
        cid: DoubleRatchet.chainId(stranger.pk), rk: stranger.pk, kemCt: forged.ct, n: 0, pn: 0))
    check(refused == nil, "a step whose payload does not authenticate is refused")
    check(hx(alice.state.root) == rootBefore, "…and the root is left untouched")
}

// --- The step policy is count-first, with time as the backstop -------------
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    let t0 = Date()
    _ = openMsg(&bobState, sendMsg(&alice.state, at: t0)!)
    let reply = sendMsg(&bobState, at: t0)!
    _ = openMsg(&alice.state, reply)   // Alice learns Bob's key, so she can step

    // A chain that has SENT NOTHING never pays for a step, however old it is.
    // This is the half of the documented policy that was missing from the code.
    var fresh = alice.state
    fresh.sentOnChain = 0
    check(!RatchetSession.shouldStep(fresh, now: t0.addingTimeInterval(
              DoubleRatchet.ratchetMinStepInterval * 10)),
          "an unused chain does not step, however long it has existed")

    // Count is the primary trigger: a busy conversation steps on volume.
    var busy = alice.state
    busy.sentOnChain = DoubleRatchet.ratchetMaxMessagesPerChain
    busy.chainStartedAt = t0
    check(RatchetSession.shouldStep(busy, now: t0.addingTimeInterval(1)),
          "a chain at the message cap steps immediately")

    // Time is the backstop, and it is now long enough that an ordinary reply a
    // few minutes later does NOT drag a ~29 kB step along with it. That was the
    // whole cost: at 60 s every message in a slow conversation carried one.
    var slow = alice.state
    slow.sentOnChain = 1
    slow.chainStartedAt = t0
    check(!RatchetSession.shouldStep(slow, now: t0.addingTimeInterval(5 * 60)),
          "a reply 5 minutes later is cheap")
    check(!RatchetSession.shouldStep(slow, now: t0.addingTimeInterval(10 * 60)),
          "…and so is one at 10 minutes")
    check(RatchetSession.shouldStep(slow, now: t0.addingTimeInterval(
              DoubleRatchet.ratchetMinStepInterval)),
          "…and the backstop still fires")
}

// --- Regression: a FORGED step cannot destroy a live session ---------------
// The critical finding. Nothing in the frame below was ever encapsulated to
// Alice — `rk` and `kemCt` are simply random bytes of the right shape — and
// HQC's implicit rejection means the KEM will not say so. Before the AEAD gate,
// this one frame replaced Alice's root, adopted the sender's ratchet key and
// reset her receive chain, and ConversationRouter then persisted the wreckage.
// Bob's real messages could never be read again, and no re-handshake could
// recover it: a fresh `init` is refused as a replay by anyone who has heard
// from you. Any accepted friend could send it.
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    _ = openMsg(&bobState, sendMsg(&alice.state)!)
    let fromBob = sendMsg(&bobState)!
    check(openMsg(&alice.state, fromBob) == fromBob.key, "the session is live")

    let rootBefore = hx(alice.state.root)
    let peerRkBefore = hx(alice.state.peerRkPub!)
    let recvBefore = alice.state.recv!

    let junkRk = randomData(32)
    let refused = openForged(&alice.state, RatchetHeader(
        cid: DoubleRatchet.chainId(junkRk), rk: junkRk, kemCt: randomData(64), n: 0, pn: 0))
    check(refused == nil, "the forged step yields no key")
    check(hx(alice.state.root) == rootBefore, "the root did not move")
    check(hx(alice.state.peerRkPub!) == peerRkBefore, "the sender's key was not adopted")
    check(alice.state.recv! == recvBefore, "the receive chain did not reset")

    // The statement that actually matters: the conversation still works.
    let next = sendMsg(&bobState)!
    check(openMsg(&alice.state, next) == next.key, "Bob's next real message still decrypts")
}

// --- Regression: a forged step cannot evict genuinely skipped keys ---------
// The tail-walk that retires the outgoing chain used to run BEFORE the
// decapsulation, and `cacheSkipped` evicts once the array passes maxSkipped. So
// a frame repeated with a growing `pn` — attacker-chosen, and never
// authenticated — pushed out the keys for messages the real peer had sent and
// that had not arrived yet. Those messages then never decrypted. On iOS the walk
// also runs on the MainActor, so it was a free main-thread stall as well.
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    _ = openMsg(&bobState, sendMsg(&alice.state)!)

    // Bob's first reply steps, which is what gives Alice his chain to count in.
    let opener = sendMsg(&bobState)!
    check(openMsg(&alice.state, opener) == opener.key, "Alice is on Bob's chain")

    // Three more; Alice receives only the third, so the first two are cached as
    // skipped keys waiting for a delivery that is still in flight.
    let inFlight = [sendMsg(&bobState)!, sendMsg(&bobState)!, sendMsg(&bobState)!]
    check(openMsg(&alice.state, inFlight[2]) == inFlight[2].key, "the newest opens")
    check(alice.state.skipped.count == 2, "the two undelivered positions are cached")
    let cachedBefore = alice.state.skipped

    var allRefused = true
    for pn in 1...50 {
        let junkRk = randomData(32)
        let got = openForged(&alice.state, RatchetHeader(
            cid: DoubleRatchet.chainId(junkRk), rk: junkRk, kemCt: randomData(64),
            n: 0, pn: pn * 40))
        if got != nil { allRefused = false }
    }
    check(allRefused, "every forged step is refused")
    check(alice.state.skipped == cachedBefore, "no cached key was evicted, walked over or added")

    // And the stragglers still open when they finally land.
    check(openMsg(&alice.state, inFlight[0]) == inFlight[0].key, "straggler 0 resolves")
    check(openMsg(&alice.state, inFlight[1]) == inFlight[1].key, "straggler 1 resolves")
}

// --- Regression: a cached key is not burned by a frame that fails its tag --
// The same mistake as the step branch, on a quieter path: `takeSkipped` used to
// remove the entry before the caller could check the tag, so one corrupt frame
// at a skipped position destroyed the key for the real message there.
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    _ = openMsg(&bobState, sendMsg(&alice.state)!)
    let opener = sendMsg(&bobState)!
    check(openMsg(&alice.state, opener) == opener.key, "Alice is on Bob's chain")

    let straggler = sendMsg(&bobState)!
    let arrivesFirst = sendMsg(&bobState)!
    check(openMsg(&alice.state, arrivesFirst) == arrivesFirst.key, "the later frame opens")
    check(alice.state.skipped.count == 1, "the straggler's key is cached")

    check(openForged(&alice.state, straggler.header) == nil, "a bad tag gets nothing")
    check(alice.state.skipped.count == 1, "and the cached key is still there")

    check(openMsg(&alice.state, straggler) == straggler.key, "the real straggler still opens")
    check(alice.state.skipped.isEmpty, "and consumes the entry when it does")
}

// --- Regression: replaying an old step must not rewind the ratchet --------
// `open` processes the header BEFORE the payload authenticates it, so a
// byte-identical replay of a real stepping frame reaches the step logic with a
// ciphertext that still decapsulates (our ratchet secret only rotates when WE
// send). Re-applying it would recompute the root from the CURRENT root rather
// than the one that step originally advanced, and the two sides would diverge
// permanently — the same failure class as TM-1.
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    _ = openMsg(&bobState, sendMsg(&alice.state)!)

    // Bob steps twice with Alice never sending, so her ratchet secret does not
    // rotate and BOTH step ciphertexts stay decapsulable by her.
    var clock = Date()
    let stepOne = sendMsg(&bobState, at: clock)!
    check(stepOne.header.rk != nil, "first step")
    check(openMsg(&alice.state, stepOne) == stepOne.key, "A follows step one")

    clock = clock.addingTimeInterval(DoubleRatchet.ratchetMinStepInterval + 1)
    let stepTwo = sendMsg(&bobState, at: clock)!
    check(stepTwo.header.rk != nil, "second step")
    check(openMsg(&alice.state, stepTwo) == stepTwo.key, "A follows step two")

    let rootAfterTwo = hx(alice.state.root)
    check(openMsg(&alice.state, stepOne) == nil, "the replayed step yields no key")
    check(hx(alice.state.root) == rootAfterTwo, "…and the root did not move")

    // Both directions still work.
    clock = clock.addingTimeInterval(DoubleRatchet.ratchetMinStepInterval + 1)
    let afterA = sendMsg(&alice.state, at: clock)!
    check(openMsg(&bobState, afterA) == afterA.key, "A→B survives the replay")
    clock = clock.addingTimeInterval(DoubleRatchet.ratchetMinStepInterval + 1)
    let afterB = sendMsg(&bobState, at: clock)!
    check(openMsg(&alice.state, afterB) == afterB.key, "B→A survives the replay")
    check(hx(alice.state.root) == hx(bobState.root), "the two roots are still equal")
}

// --- The one-time prekey is optional --------------------------------------
do {
    let bob = try! StubPeer(kem: kem, oneTimeCount: 0)
    let bundle = bob.bundle()
    check(bundle.oneTimePk == nil, "the directory served the medium-term key only")

    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bundle)
    check(alice.header.ctOt == nil, "no one-time encapsulation travels")
    let first = sendMsg(&alice.state)!
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)
    check(bobState != nil, "the medium-term fallback starts a session")
    check(openMsg(&bobState!, first) == first.key, "…and it decrypts")
}

// --- An init naming a spent one-time key is refused ------------------------
do {
    let bob = try! StubPeer(kem: kem, oneTimeCount: 1)
    let alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    // Bob consumed that key already — a duplicate or replayed init.
    check(RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(spent: true),
                                          header: alice.header) == nil,
          "no root is derived from a partial secret set")
}

// --- Two sessions with the same peer share no key material ----------------
do {
    let bob = try! StubPeer(kem: kem, oneTimeCount: 2)
    let one = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle(0))
    let two = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle(1))
    check(hx(one.state.root) != hx(two.state.root), "distinct roots")
    check(hx(one.state.send!.ck) != hx(two.state.send!.ck), "distinct chains")

    // Even the SAME one-time key twice must not collide — the encapsulations are
    // independently random.
    let three = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle(0))
    check(hx(one.state.root) != hx(three.state.root), "re-claiming a key still differs")
}

// --- State survives the Keychain round trip -------------------------------
// The session is JSON in the Keychain, so anything Codable drops is state the
// app silently loses on relaunch.
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    var bobState = RatchetSession.startAsResponder(kem: kem, secrets: bob.secrets(),
                                                   header: alice.header)!
    _ = openMsg(&bobState, sendMsg(&alice.state)!)
    let stepped = sendMsg(&bobState)!
    _ = openMsg(&alice.state, stepped)
    // Leave a straggler in the cache so `skipped` is non-empty.
    _ = sendMsg(&alice.state)
    let far = sendMsg(&alice.state)!
    _ = openMsg(&bobState, far)
    check(!bobState.skipped.isEmpty, "there is cached state worth preserving")

    let encoded = try! JSONEncoder().encode(bobState)
    let restored = try! JSONDecoder().decode(RatchetSessionState.self, from: encoded)
    check(restored == bobState, "the whole session round-trips through JSON")
    check(restored.v == RatchetSession.protocolVersion, "and carries its version")

    // A restored session must still decrypt.
    var revived = restored
    let next = sendMsg(&alice.state)!
    check(openMsg(&revived, next) == next.key, "a restored session still opens messages")
}

// --- Regression: the handshake survives a relaunch before the first send ----
// The init header used to live in a side map in memory. An app restart between
// opening a session and sending stranded it: `hasSession` was true, so nothing
// re-opened the session, but the peer had never been told it existed and every
// message after was undeliverable with nothing anywhere saying why.
do {
    let bob = try! StubPeer(kem: kem)
    var alice = try! RatchetSession.startAsInitiator(kem: kem, bundle: bob.bundle())
    check(alice.state.pendingInit != nil, "a fresh initiator session carries its handshake")

    // Relaunch: everything not persisted is gone.
    let revived = try! JSONDecoder().decode(
        RatchetSessionState.self, from: try! JSONEncoder().encode(alice.state))
    check(revived.pendingInit != nil, "…and it survives the Keychain round trip")

    var sender = revived
    let first = sendMsg(&sender)!
    check(sender.pendingInit != nil,
          "the handshake is still attached — a failed send must not lose it")

    // Every frame carries it until the peer answers, so a retry works too.
    let retry = sendMsg(&sender)!
    check(sender.pendingInit != nil, "…on a retry as well")

    // The peer opens the session from the revived header and reads both frames.
    var bobState = RatchetSession.startAsResponder(
        kem: kem, secrets: bob.secrets(), header: revived.pendingInit!)
    check(bobState != nil, "the peer opens a session from the revived handshake")
    check(openMsg(&bobState!, first) == first.key, "the first message decrypts")
    check(openMsg(&bobState!, retry) == retry.key, "and so does the retry")

    // Once the peer answers, the handshake stops riding along.
    let reply = sendMsg(&bobState!)!
    check(openMsg(&sender, reply) == reply.key, "the reply opens")
    check(sender.pendingInit == nil, "hearing back clears the handshake")
    _ = alice
}


print("")
print("Simultaneous init (glare)")
// Both devices open a session at once — which became the common case the moment
// accepting an invite started sending a greeting on the user's behalf. Each side
// kept its own initiator session and threw away the other's init AND the message
// inside it, so every later frame decrypted against a session the peer had never
// heard of. The conversation was dead in both directions from its first second.
//
// The rule has to be SYMMETRIC: exactly one side may yield. Two yielders lose
// both sessions; two keepers reproduce the bug.

let lo = String(repeating: "1", count: 64)
let hi = String(repeating: "9", count: 64)

check(InitCollision.resolve(hasSession: false, heardFromThem: false, myID: lo, peerID: hi) == .open, "no session — the ordinary responder path")

// The replay guard this used to be, and must remain: once they have sent us
// anything they demonstrably hold our session, so an init is a replayed frame
// and honouring it would let anyone wipe a conversation.
check(InitCollision.resolve(hasSession: true, heardFromThem: true, myID: lo, peerID: hi) == .ignoreReplay, "established session — an init is a replay and is ignored")
check(InitCollision.resolve(hasSession: true, heardFromThem: true, myID: hi, peerID: lo) == .ignoreReplay, "…whichever id we hold")

check(InitCollision.resolve(hasSession: true, heardFromThem: false, myID: lo, peerID: hi) == .keepOurs, "glare, we hold the lower id — keep ours")
check(InitCollision.resolve(hasSession: true, heardFromThem: false, myID: hi, peerID: lo) == .yieldToTheirs, "glare, we hold the higher id — yield")

// The property that makes it converge, over ids that are not hand-picked.
var asymmetric = true
for a in 0..<24 {
    for b in 0..<24 where a != b {
        let idA = String(repeating: "0", count: 62) + String(format: "%02x", a)
        let idB = String(repeating: "0", count: 62) + String(format: "%02x", b)
        let sideA = InitCollision.resolve(hasSession: true, heardFromThem: false, myID: idA, peerID: idB)
        let sideB = InitCollision.resolve(hasSession: true, heardFromThem: false, myID: idB, peerID: idA)
        let yielders = [sideA, sideB].filter { $0 == .yieldToTheirs }.count
        if yielders != 1 { asymmetric = false }
    }
}
check(asymmetric, "across 552 id pairs, exactly one side yields every time")

// Degenerate, but it must not yield a session to itself and lose it.
check(InitCollision.resolve(hasSession: true, heardFromThem: false, myID: lo, peerID: lo) == .keepOurs, "an equal id keeps rather than yields")

finish()
