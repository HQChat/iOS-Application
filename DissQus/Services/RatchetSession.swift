//
//  RatchetSession.swift
//  DissQus
//
//  The double-ratchet state machine, driven over an injected KEM. Mirrors
//  services/server/lib/ratchet-session.ts.
//
//  Split from DoubleRatchet.swift for the same reason the TypeScript is split:
//  that module stays pure and pinnable by cross-implementation vectors, and this
//  one can be exercised with a stub KEM on any machine — the real HQC library is
//  a native binary and the Swift test runner has no linkage to it.
//
//  ── The shape of a session ──────────────────────────────────────────────────
//  Roles are asymmetric only for the first message. The INITIATOR claims the
//  responder's prekeys, derives root_0 plus its own first sending chain, and
//  sends `init`. The RESPONDER decapsulates, derives the same pair as its
//  receiving chain, and performs the first real ratchet step when it replies.
//  After that the two are interchangeable.
//
//  ── What is deliberately NOT here ───────────────────────────────────────────
//  Nothing in this file authenticates the peer. That comes from `ssId` being
//  encapsulated to a TOFU-pinned identity key, which the caller decides. A
//  session built against an unpinned key is a session with whoever the server
//  said it was.
//

import Foundation

/// The KEM this ratchet rides on. HQC in the app, a stub in tests.
protocol RatchetKem {
    func generateKeypair() throws -> (pk: Data, sk: Data)
    func encapsulate(_ pk: Data) throws -> (ct: Data, ss: Data)
    func decapsulate(sk: Data, ct: Data) throws -> Data
}

// MARK: - Persisted state

/// One direction's symmetric chain.
struct RatchetChain: Codable, Equatable {
    var ck: Data
    /// Next index this chain will produce or expect.
    var n: Int
}

struct SkippedMessageKey: Codable, Equatable {
    /// `DoubleRatchet.chainId` of the ratchet key whose chain produced it.
    var chain: String
    var n: Int
    var key: Data
}

/// Everything a conversation needs, JSON-encoded into the Keychain.
struct RatchetSessionState: Codable, Equatable {
    /// Protocol version. State that is not this is deleted rather than migrated
    /// — nothing here has shipped, so a re-handshake is cheaper and safer than a
    /// migration path nobody will ever exercise twice.
    var v: Int = RatchetSession.protocolVersion

    var root: Data
    /// My ratchet keypair. Peers encapsulate to `rkPub`; `rkSec` opens their step.
    var rkPub: Data
    var rkSec: Data
    /// The peer's advertised ratchet key. Nil until the initiator hears back.
    var peerRkPub: Data?
    var send: RatchetChain?
    var recv: RatchetChain?
    /// Length of the previous sending chain — the `pn` header field.
    var prevSendN: Int
    var skipped: [SkippedMessageKey]
    /// Chains already stepped into, most recent last. Without this, a replayed
    /// stepping frame is re-applied: `open` must read the header before the
    /// payload can authenticate it, and the replay still decapsulates because
    /// our ratchet secret only rotates when WE send. It would then recompute the
    /// root from the current root instead of the one that step advanced, and the
    /// two sides would diverge for good.
    var seenChains: [String]
    /// The handshake header, carried on EVERY outbound frame until we hear back
    /// from the peer. Nil on the responder side.
    ///
    /// Cleared on the first successful `open`, not on the first `seal`. Clearing
    /// it when we send would lose it whenever the publish failed or the send was
    /// retried — the retry would go out as a plain `msg` naming a session the
    /// peer had never been told about, undeliverable forever with nothing to say
    /// why. Receiving anything from them is the only proof they have the session.
    ///
    /// The cost is that the handshake ciphertexts (~43 kB) repeat on each message
    /// until they reply. That is the right trade: it is bounded by one reply, and
    /// the alternative silently drops conversations.
    var pendingInit: RatchetInitHeader?
    /// Messages sent on the current sending chain, for the step policy.
    var sentOnChain: Int
    /// When the current sending chain started, for the step policy.
    var chainStartedAt: Date
}

/// The per-message header. Every field is bound as AEAD additional data.
struct RatchetHeader: Equatable {
    /// `chainId` of the sender's current ratchet key — on EVERY message, because
    /// `n` restarts at 0 on each chain and a bare straggler would otherwise be
    /// read against the wrong one.
    var cid: String
    /// Present only on a step.
    var rk: Data?
    var kemCt: Data?
    var n: Int
    var pn: Int
}

/// What the initiator must put in an `init` frame besides the sealed payload.
///
/// Codable because it is PERSISTED inside the session until the first frame goes
/// out. Holding it only in memory would mean an app restart between opening a
/// session and sending left a session that exists locally but that the peer was
/// never told about — `hasSession` true, every subsequent message undeliverable,
/// and nothing anywhere saying why.
struct RatchetInitHeader: Codable, Equatable {
    var ctId: Data
    var ctMt: Data
    var ctOt: Data?
    var otId: Int?
    var rk: Data
    var cid: String
}

/// The peer's published bundle, as claimed from the directory.
struct PrekeyBundle {
    var identityPk: Data
    var mediumPk: Data
    /// Nil when the peer's one-time pool was exhausted.
    var oneTimePk: Data?
    var oneTimeId: Int?
}

/// My own prekey secrets, needed to answer an `init`.
struct PrekeySecrets {
    var identitySk: Data
    var mediumSk: Data
    /// Looked up by the `otId` the initiator echoed back.
    var oneTimeSk: (Int) -> Data?
}

// MARK: - Core

/// What to do with an inbound `init` when a session already exists.
///
/// Two situations hide behind "we already have a session" and they need opposite
/// answers, so the choice is made here — pure, and identically on both devices.
enum InitCollision: Equatable {
    /// No session yet: the ordinary responder path.
    case open
    /// We have heard from them, so they hold our session. An init now is a
    /// replay, and honouring it would let anyone wipe a conversation by
    /// re-sending an old frame.
    case ignoreReplay
    /// Both sides started at once and we hold the lower id. Keep ours; they
    /// will yield when ours arrives.
    case keepOurs
    /// Both sides started at once and we hold the higher id. Drop ours, adopt
    /// theirs, and re-send what they never received.
    case yieldToTheirs

    /// - Parameters:
    ///   - hasSession: whether a session already exists for this contact.
    ///   - heardFromThem: whether they have ever sent us anything on it —
    ///     `pendingInit == nil`. If they have not, they cannot be holding our
    ///     session, so a collision is a genuine simultaneous start rather than
    ///     a replay.
    ///   - myID / peerID: client ids. The lower one keeps its session. Same
    ///     ordering the conversation topic uses (friendshipHash sorts the pair),
    ///     so there is one rule in the system rather than two that could drift
    ///     apart — and because both sides compare the same two values, exactly
    ///     one of them yields.
    static func resolve(hasSession: Bool, heardFromThem: Bool,
                        myID: String, peerID: String) -> InitCollision {
        guard hasSession else { return .open }
        if heardFromThem { return .ignoreReplay }
        // Equal ids would mean talking to ourselves; nothing to converge on, and
        // keeping is the safe half (it changes no state).
        return myID < peerID ? .keepOurs : (myID == peerID ? .keepOurs : .yieldToTheirs)
    }
}

enum RatchetSession {

    /// Bumped whenever the on-disk shape or the KDFs change. State at any other
    /// version is discarded, not migrated.
    static let protocolVersion = 2

    /// How many retired chains to remember for replay rejection. A step only
    /// lands if its ciphertext still decapsulates under our CURRENT ratchet
    /// secret, and that rotates every time we send a step — so a replay older
    /// than this is already refused by the KEM. This covers the window where it
    /// is not.
    static let maxSeenChains = 64

    // MARK: Starting a session

    /// Initiator side: derive root_0 from the peer's bundle and open a sending
    /// chain, so the very first message is already ratcheted and can be sent
    /// while the peer is offline.
    ///
    /// Three encapsulations, each doing a different job:
    ///   - to the pinned IDENTITY key: authenticates the peer. Without it, a
    ///     server that substituted a prekey would be talking to us as them.
    ///   - to the MEDIUM-term prekey: forward secrecy with a rotation-length window.
    ///   - to a ONE-TIME prekey when one was available: forward secrecy that ends
    ///     the moment the responder consumes it.
    static func startAsInitiator(
        kem: RatchetKem,
        bundle: PrekeyBundle,
        now: Date = Date()
    ) throws -> (state: RatchetSessionState, header: RatchetInitHeader) {
        let id = try kem.encapsulate(bundle.identityPk)
        let mt = try kem.encapsulate(bundle.mediumPk)
        let ot = try bundle.oneTimePk.map { try kem.encapsulate($0) }

        let derived = DoubleRatchet.initRoot(ssId: id.ss, ssMt: mt.ss, ssOt: ot?.ss)
        let mine = try kem.generateKeypair()
        let header = RatchetInitHeader(
            ctId: id.ct, ctMt: mt.ct, ctOt: ot?.ct, otId: bundle.oneTimeId,
            rk: mine.pk, cid: DoubleRatchet.chainId(mine.pk)
        )

        let state = RatchetSessionState(
            root: derived.root,
            rkPub: mine.pk,
            rkSec: mine.sk,
            // Not the peer's prekey: that key is single-use and the responder may
            // have already dropped its secret. The peer advertises a real ratchet
            // key on its first reply, and only then can we step.
            peerRkPub: nil,
            send: RatchetChain(ck: derived.chain, n: 0),
            recv: nil,
            prevSendN: 0,
            skipped: [],
            seenChains: [],
            pendingInit: header,
            sentOnChain: 0,
            chainStartedAt: now
        )
        return (state, header)
    }

    /// Responder side: rebuild the same root from an `init` frame and open the
    /// matching receiving chain.
    ///
    /// Returns nil when a ciphertext does not decapsulate — a forged or corrupt
    /// frame, or an `otId` whose secret this device no longer holds (a duplicate
    /// `init`, or one built on a key already consumed). A nil must NOT tear down
    /// an existing session: that is exactly how a replayed `init` would become a
    /// way to reset someone's conversation.
    static func startAsResponder(
        kem: RatchetKem,
        secrets: PrekeySecrets,
        header: RatchetInitHeader,
        now: Date = Date()
    ) -> RatchetSessionState? {
        do {
            let ssId = try kem.decapsulate(sk: secrets.identitySk, ct: header.ctId)
            let ssMt = try kem.decapsulate(sk: secrets.mediumSk, ct: header.ctMt)

            var ssOt: Data?
            if let ctOt = header.ctOt {
                // A one-time secret we no longer hold means this init cannot be
                // answered as sent. Failing here is right: deriving a root from
                // two of the three secrets would silently disagree with the
                // initiator's three.
                guard let otId = header.otId, let sk = secrets.oneTimeSk(otId) else { return nil }
                ssOt = try kem.decapsulate(sk: sk, ct: ctOt)
            }

            let derived = DoubleRatchet.initRoot(ssId: ssId, ssMt: ssMt, ssOt: ssOt)
            let mine = try kem.generateKeypair()

            return RatchetSessionState(
                root: derived.root,
                rkPub: mine.pk,
                rkSec: mine.sk,
                peerRkPub: header.rk,
                send: nil,  // opened by the first step, taken when we reply
                recv: RatchetChain(ck: derived.chain, n: 0),
                prevSendN: 0,
                skipped: [],
                // The initiator's chain counts as entered: a replayed init must
                // not be able to re-derive it later as though it were a step.
                seenChains: [DoubleRatchet.chainId(header.rk)],
                pendingInit: nil,  // the responder answers, it does not initiate
                sentOnChain: 0,
                chainStartedAt: now
            )
        } catch {
            return nil
        }
    }

    // MARK: Sending

    /// Whether the next send should perform an asymmetric step.
    ///
    /// A step is only possible once the peer has advertised a ratchet key.
    /// Beyond that it is a cost decision (a step costs ~29 kB): step when the
    /// current chain has run long enough or lived long enough, and always when
    /// there is no sending chain at all — the responder's first reply, which is
    /// the moment the ratchet actually starts turning.
    static func shouldStep(_ state: RatchetSessionState, now: Date = Date()) -> Bool {
        guard state.peerRkPub != nil else { return false }
        guard state.send != nil else { return true }
        // "used at least once" — the half of the documented policy that was
        // never in the code. A chain that has sent nothing has nothing to rotate
        // away from, so stepping off it spends ~29 kB to move from one unused
        // chain to another.
        if state.sentOnChain == 0 { return false }
        if state.sentOnChain >= DoubleRatchet.ratchetMaxMessagesPerChain { return true }
        return now.timeIntervalSince(state.chainStartedAt) >= DoubleRatchet.ratchetMinStepInterval
    }

    /// Take the next sending key, stepping the ratchet first when policy says
    /// to. The returned header must travel with the ciphertext and be bound as
    /// its AEAD additional data.
    static func seal(
        kem: RatchetKem,
        state: inout RatchetSessionState,
        now: Date = Date()
    ) throws -> (key: Data, header: RatchetHeader, initHeader: RatchetInitHeader?) {
        var stepRk: Data?
        var stepCt: Data?

        if shouldStep(state, now: now), let peerRk = state.peerRkPub {
            let enc = try kem.encapsulate(peerRk)
            let next = DoubleRatchet.rootStep(root: state.root, ss: enc.ss)

            // A fresh keypair per step is the point: the old secret is dropped,
            // so a later compromise cannot open ciphertexts naming the old key.
            let mine = try kem.generateKeypair()
            state.root = next.root
            state.prevSendN = state.send?.n ?? 0
            state.send = RatchetChain(ck: next.chain, n: 0)
            state.rkPub = mine.pk
            state.rkSec = mine.sk
            state.sentOnChain = 0
            state.chainStartedAt = now
            stepRk = mine.pk
            stepCt = enc.ct
        }

        guard var send = state.send else {
            // Only reachable if a responder sends before it ever received, which
            // startAsResponder makes impossible: it always opens a recv chain
            // and sets peerRkPub, so shouldStep returns true above.
            throw RatchetSessionError.noSendingChain
        }

        let key = DoubleRatchet.messageKey(send.ck)
        let header = RatchetHeader(
            // Always the sender's CURRENT chain, stepping or not — this is what
            // lets the receiver tell which chain `n` counts within.
            cid: DoubleRatchet.chainId(state.rkPub),
            rk: stepRk,
            kemCt: stepCt,
            n: send.n,
            pn: state.prevSendN
        )
        send.ck = DoubleRatchet.chainNext(send.ck)
        send.n += 1
        state.send = send
        state.sentOnChain += 1
        // Deliberately NOT cleared here — see `pendingInit`.
        return (key, header, state.pendingInit)
    }

    // MARK: Receiving

    /// Message key for an inbound header, or nil if there is none to be had.
    ///
    /// `verify` is the AEAD open, and in this protocol it is the ONLY
    /// authenticator. Nothing here writes to `state` until it has returned true.
    ///
    /// That is not defensive style, it is the fix for a specific failure. HQC
    /// uses IMPLICIT REJECTION: decapsulating a forged or corrupt ciphertext
    /// returns a pseudo-random secret and no error (services/server/lib/hqc.ts
    /// says so outright). So a fabricated step — a random `rk` and 14421 random
    /// bytes as `kemCt` — reaches `rootStep` and succeeds. When this function
    /// committed before the tag was checked, that one frame replaced the root,
    /// adopted the sender's ratchet key and reset the receive chain; the AEAD
    /// then failed, and ConversationRouter saved the wreckage anyway. The two
    /// sides could never converge again, and no re-handshake could rescue it —
    /// a fresh `init` is refused as a replay by anyone who has heard from you.
    /// Any accepted friend could send that frame.
    ///
    /// The KEM cannot tell us a step was forged, and no amount of care here will
    /// change that. The tag can. So the tag decides — and to make that
    /// impossible to get wrong at a call site, this function performs the commit
    /// itself rather than handing back a key and trusting its callers.
    ///
    /// A nil is an ordinary outcome — a replay, a frame from a retired chain, a
    /// gap too large to bridge, or a payload that did not authenticate — and
    /// must not be surfaced to the user as an error.
    static func open(
        kem: RatchetKem,
        state: inout RatchetSessionState,
        header: RatchetHeader,
        verify: (Data) -> Bool
    ) -> Data? {
        guard header.n >= 0, header.pn >= 0 else { return nil }
        guard header.cid.count == 32,
              header.cid.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) })
        else { return nil }

        // A key cached while `cid`'s chain was current, for a message that
        // arrived late — including one from a chain since retired. Checked first
        // precisely so a straggler resolves without touching any live state.
        //
        // Consumed only if it WORKS. Removing it before the tag check would let
        // one corrupt frame at a skipped position destroy the key for the real
        // message that position belongs to: the same "spend state on an
        // unauthenticated frame" mistake as the step branch below, on a much
        // quieter path.
        if let i = findSkipped(state, chain: header.cid, n: header.n) {
            let key = state.skipped[i].key
            guard verify(key) else { return nil }
            state.skipped.remove(at: i)
            return key
        }

        let currentCid = state.peerRkPub.map { DoubleRatchet.chainId($0) }

        // From here everything is computed into LOCALS. `state` is untouched
        // until `verify` has passed — see the note on this function.
        var root = state.root
        var peerRkPub = state.peerRkPub
        var recv = state.recv
        /// Set on a step: the tail of the chain being retired, and which chain.
        var tail: (cid: String, keys: [(n: Int, key: Data)])?
        /// Set on a step: the chain being entered, to remember once committed.
        var enteredCid: String?

        if header.cid != currentCid {
            // Not the chain we are on. The ONLY way to move is a well-formed step
            // into a chain we have never entered.
            guard let rk = header.rk, let kemCt = header.kemCt else { return nil }
            // `cid` must actually name the key it travels with, or the two
            // selectors could disagree and pick different chains on each side.
            guard DoubleRatchet.chainId(rk) == header.cid else { return nil }
            // Refuse to re-enter a retired chain — see `seenChains`.
            guard !state.seenChains.contains(header.cid) else { return nil }

            // A LENGTH mismatch, and nothing else: HQCService throws on a
            // wrong-sized ciphertext and returns a pseudo-random secret for every
            // other bad input. Reaching this line does not mean "forged", and
            // never did.
            guard let ss = try? kem.decapsulate(sk: state.rkSec, ct: kemCt) else {
                return nil
            }

            // Finish the chain we were on. `pn` says how long it ran, so anything
            // we never saw from it is cached rather than lost — the fine-grained
            // version of v1's one-epoch `prev` window.
            //
            // Computed BELOW the decapsulation and applied only past the `verify`
            // gate, because `pn` is attacker-chosen and `cacheSkipped` EVICTS.
            // Run eagerly, a repeated frame with a growing `pn` walks up to
            // maxSkipped keys each time — on the MainActor — and pushes out the
            // keys for real messages still in flight, which then never decrypt.
            // Retiring a chain is bookkeeping for a step, and the step is exactly
            // what has not been established yet.
            if let current = recv, let currentCid {
                let remaining = header.pn - current.n
                if remaining > 0, remaining <= DoubleRatchet.maxSkipped,
                   let walked = DoubleRatchet.walkChain(ck: current.ck, fromN: current.n,
                                                        targetN: header.pn - 1) {
                    var keys = walked.skipped
                    keys.append((n: header.pn - 1, key: walked.messageKey))
                    tail = (cid: currentCid, keys: keys)
                }
            }

            let next = DoubleRatchet.rootStep(root: root, ss: ss)
            root = next.root
            peerRkPub = rk
            recv = RatchetChain(ck: next.chain, n: 0)
            enteredCid = header.cid
        }

        guard let current = recv else { return nil }
        guard header.n >= current.n else { return nil }  // consumed, and not cached
        guard let walk = DoubleRatchet.walkChain(ck: current.ck, fromN: current.n,
                                                 targetN: header.n) else {
            return nil  // gap past maxSkipped — refused without walking it
        }

        // The sole authenticator. Everything above this line was a candidate.
        guard verify(walk.messageKey) else { return nil }

        // ── Commit ──────────────────────────────────────────────────────────
        if let enteredCid {
            state.root = root
            state.peerRkPub = peerRkPub
            if let tail { cacheSkipped(&state, chain: tail.cid, keys: tail.keys) }
            rememberChain(&state, enteredCid)
        }
        cacheSkipped(&state, chain: header.cid, keys: walk.skipped)
        state.recv = RatchetChain(ck: walk.ck, n: walk.nextN)
        // Hearing from them is the proof they hold the session, so the handshake
        // no longer needs to ride every frame.
        state.pendingInit = nil
        return walk.messageKey
    }

    // MARK: Skipped-key cache

    /// Index of a cached key, or nil. Deliberately does NOT remove it: the
    /// caller consumes it only once the payload has authenticated, so a corrupt
    /// frame at a skipped position cannot burn the key for the real message that
    /// belongs there.
    private static func findSkipped(_ state: RatchetSessionState, chain: String, n: Int) -> Int? {
        state.skipped.firstIndex(where: { $0.chain == chain && $0.n == n })
    }

    /// Cache keys skipped on the way to a delivered one, bounded by maxSkipped.
    ///
    /// Deliberately still a linear array rather than a dictionary keyed on
    /// "{chain}:{n}". Measured, a worst-case `findSkipped` over a FULL
    /// 2000-entry cache costs ~14 microseconds per inbound frame, while
    /// JSON-encoding that same cache into the Keychain — which happens on every
    /// save, and which an index does not help at all — costs ~392, twenty-eight
    /// times more. The index buys the small half of the win.
    ///
    /// It costs the persisted shape, which is not a fair trade: a change to
    /// `skipped` means bumping `protocolVersion`, and that DELETES the session
    /// rather than migrating it — with no recovery, because a re-`init` from a
    /// peer who has heard from you is refused as a replay. A 14-microsecond
    /// saving is not worth standing anywhere near that.
    private static func cacheSkipped(
        _ state: inout RatchetSessionState,
        chain: String,
        keys: [(n: Int, key: Data)]
    ) {
        for k in keys {
            state.skipped.append(SkippedMessageKey(chain: chain, n: k.n, key: k.key))
        }
        // Oldest first — the cache is append-ordered, so the head is the least
        // likely to still be in flight.
        if state.skipped.count > DoubleRatchet.maxSkipped {
            state.skipped.removeFirst(state.skipped.count - DoubleRatchet.maxSkipped)
        }
    }

    private static func rememberChain(_ state: inout RatchetSessionState, _ cid: String) {
        state.seenChains.append(cid)
        if state.seenChains.count > maxSeenChains {
            state.seenChains.removeFirst(state.seenChains.count - maxSeenChains)
        }
    }
}

enum RatchetSessionError: Error, LocalizedError {
    case noSendingChain

    var errorDescription: String? {
        switch self {
        case .noSendingChain:
            return "This conversation has no sending chain yet."
        }
    }
}
