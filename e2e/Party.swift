//
//  Party.swift
//  DissQus end-to-end harness
//
//  One participant, driving the REAL implementation.
//
//  Everything that carries protocol meaning is the app's own code, compiled from
//  DissQus/Services: the ratchet (RatchetSession, DoubleRatchet), the wire
//  (ConversationFrame and both envelope versions), the AEAD (AESService), the
//  identity commitment (PeerID), the topic vocabulary (MQTTTopics) and the
//  initiator-authentication exchange (Handshake). The KEM is real HQC through
//  the app's own adapter (HQCKem → HQCService → libhqc_wrap), not a stub.
//
//  ── What this file re-implements, and why that is honest ────────────────────
//  The ORCHESTRATION — hold an inbound `init`, challenge its sender, answer a
//  challenge for a handshake we started, open the init on a valid proof — lives
//  in ConversationRouter, which is `@MainActor` and built on SwiftData. Pulling
//  that in would mean a model container, a Keychain, a profile and a biometric
//  prompt, none of which says anything about the protocol.
//
//  So the state machine below mirrors ConversationRouter's, and that is a real
//  caveat: a divergence between the two would not be caught here. It is written
//  to be read side by side with the original, and the comments point at it.
//  Everything BELOW the orchestration is the shipping code, byte for byte.
//

import Foundation
import CryptoKit

/// A prekey bundle, as the directory would serve it.
struct PublishedBundle {
    let identityPk: Data
    let mediumPk: Data
    var oneTimePk: Data?
    var oneTimeId: Int?
}

final class Party {

    let name: String
    let id: String
    let identityPk: Data
    private let identitySk: Data

    private let kem: RatchetKem = HQCKem()
    private let bus: FileBus

    /// The directory's view: peer id → their identity public key. Populated by
    /// the friend request, and every entry is checked against the id it claims
    /// before it is kept — `PeerID.matches` is what makes an id a commitment.
    private var pinned: [String: Data] = [:]

    /// Sessions, one per peer.
    private(set) var sessions: [String: RatchetSessionState] = [:]

    /// Round-trip every session through JSON, as persistence does.
    ///
    /// `RatchetSessionState` is Codable because it is STORED — the app writes it
    /// into the Keychain on every save and reads it back on launch, so the
    /// encoded shape is load-bearing in a way the in-memory struct is not. The
    /// comment on `cacheSkipped` spells out the stakes: changing `skipped` means
    /// bumping `protocolVersion`, which DELETES the session rather than migrating
    /// it, with no recovery, because a re-`init` from a peer who has already
    /// heard from you is refused as a replay.
    ///
    /// Nothing exercised that path end to end. Every test held one session in
    /// memory for its whole life, so a field that failed to survive encoding —
    /// or a decode that silently produced a different state — would not have
    /// shown up until a real client restarted mid-conversation.
    ///
    /// Throws rather than returning false: a session that cannot be re-read is
    /// the conversation gone, and a scenario should stop rather than continue
    /// against state that is quietly not what it was.
    func reloadSessionsThroughStorage() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        var restored: [String: RatchetSessionState] = [:]
        for (peer, state) in sessions {
            let bytes = try encoder.encode(state)
            restored[peer] = try decoder.decode(RatchetSessionState.self, from: bytes)
        }
        sessions = restored
    }

    /// Our own prekeys, and the secrets that open an `init` built on them.
    private var mediumSk = Data()
    private var oneTimeSk: [Int: Data] = [:]
    private(set) var bundle: PublishedBundle!

    // ── The handshake, mirroring ConversationRouter ──────────────────────────
    private struct PendingChallenge {
        let nonce: Data
        let expected: Data
        let heldInit: (frame: ConversationFrame, aad: Data)
    }
    private var pendingChallenges: [String: PendingChallenge] = [:]
    private(set) var proven: Set<String> = []

    /// What we received, in order, per peer. The transcript the integrity check
    /// is made against.
    private(set) var inbox: [(from: String, text: String, msgId: String)] = []
    /// Frames that produced nothing, with the reason. A silent drop is the
    /// failure mode this whole protocol keeps re-learning, so it is recorded.
    private(set) var drops: [String] = []
    private(set) var handshakeEvents: [String] = []

    init(name: String, bus: FileBus) throws {
        self.name = name
        self.bus = bus

        var seed = Data(count: 32)
        _ = seed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let pair = try HQCService.generateKeypair(seed: seed)
        identityPk = pair.publicKey
        identitySk = pair.secretKey
        id = PeerID.from(publicKey: pair.publicKey)
    }

    /// Publish a prekey bundle, as `PrekeyService` does against the API.
    func publishPrekeys() throws {
        let medium = try kem.generateKeypair()
        let oneTime = try kem.generateKeypair()
        mediumSk = medium.sk
        oneTimeSk[0] = oneTime.sk
        bundle = PublishedBundle(identityPk: identityPk, mediumPk: medium.pk,
                                 oneTimePk: oneTime.pk, oneTimeId: 0)
    }

    // MARK: - Friend request
    //
    // The server half of this (invite, accept, mqtt_acl rows) is exercised by
    // services/server/test/e2e. What matters HERE is the client half: a peer's
    // key is pinned only if it hashes to the id that named it.

    @discardableResult
    func acceptFriend(_ peerId: String, publicKey: Data) -> Bool {
        guard PeerID.matches(publicKey: publicKey, id: peerId) else {
            drops.append("refused a key that does not hash to \(peerId.prefix(8))…")
            return false
        }
        pinned[peerId] = publicKey
        return true
    }

    // MARK: - Sending

    /// Open a session against a claimed bundle and seal the first message.
    func startSession(with peerId: String, bundle peer: PublishedBundle) throws {
        let session = try RatchetSession.startAsInitiator(
            kem: kem,
            bundle: PrekeyBundle(identityPk: peer.identityPk, mediumPk: peer.mediumPk,
                                 oneTimePk: peer.oneTimePk, oneTimeId: peer.oneTimeId)
        )
        sessions[peerId] = session.state
    }

    /// Seal one message and put it on the bus, on whichever topic can carry it.
    @discardableResult
    func send(_ text: String, to peerId: String) throws -> String {
        guard var session = sessions[peerId] else {
            throw HarnessError.failed("\(name) has no session with \(peerId.prefix(8))…")
        }
        let sealed = try RatchetSession.seal(kem: kem, state: &session)
        let isInit = sealed.initHeader != nil
        let msgId = UUID().uuidString

        let fields = ConversationFrame(
            t: isInit ? .initiate : .message,
            sender: id,
            to: peerId,
            msgId: msgId,
            cid: sealed.header.cid,
            n: sealed.header.n,
            pn: sealed.header.pn,
            rk: sealed.initHeader?.rk ?? sealed.header.rk,
            // An init has nothing to encapsulate against, so it carries no
            // kemCt — the format refuses one outright, where v2 merely
            // tolerated it.
            kemCt: isInit ? nil : sealed.header.kemCt,
            ctId: sealed.initHeader?.ctId,
            ctMt: sealed.initHeader?.ctMt,
            ctOt: sealed.initHeader?.ctOt,
            otId: sealed.initHeader?.otId,
            senderPk: isInit ? identityPk : nil
        )
        guard let aad = fields.header() else {
            throw HarnessError.failed("\(name): the frame did not validate — \(fields.validate() ?? "?")")
        }
        let payload = try AESService.encryptRaw(plaintext: text,
                                                key: SymmetricKey(data: sealed.key), aad: aad)
        guard let bytes = fields.withPayload(payload).encoded() else {
            throw HarnessError.failed("\(name): the frame did not encode")
        }
        sessions[peerId] = session

        // An `init` goes to the peer's inbox — the only topic that can reach
        // somebody who has never subscribed to the conversation. Everything else
        // goes to the shared topic, and the receiver checks that pairing.
        let topic = isInit ? MQTTTopics.inbox(peerId) : MQTTTopics.conversation(id, peerId)
        try bus.publish(bytes, to: topic, from: id)
        return msgId
    }

    // MARK: - Receiving

    /// Drain every topic this party follows, and act on what is there.
    func poll(peers: [String]) throws {
        for peer in peers {
            for packet in try bus.receive(id, on: MQTTTopics.handshake(id, peer)) {
                try handleHandshake(packet)
            }
        }
        for packet in try bus.receive(id, on: MQTTTopics.inbox(id)) {
            try handleFrame(packet)
        }
        for peer in peers {
            for packet in try bus.receive(id, on: MQTTTopics.conversation(id, peer)) {
                try handleFrame(packet)
            }
        }
    }

    private func handleFrame(_ packet: BusPacket) throws {
        guard let (frame, aad) = ConversationFrame.decodeReporting(packet.payload).result else {
            drops.append("\(name): undecodable frame on \(packet.topic)")
            return
        }
        if frame.sender == id { return }  // our own publish, echoed back

        // A frame says who it was FOR, inside the AAD. Unconditional: under v2
        // there was no such field, so this check was skipped and the topic check
        // below carried it alone.
        if frame.to != id {
            drops.append("\(name): frame addressed to \(frame.to.prefix(8))… — not ours")
            return
        }
        // And a frame must arrive where that sender is entitled to put it.
        let expected = MQTTTopics.expected(forInit: frame.t == .initiate,
                                           sender: frame.sender, me: id)
        guard packet.topic == expected else {
            drops.append("\(name): \(frame.t == .initiate ? "init" : "msg") from "
                         + "\(frame.sender.prefix(8))… on the wrong topic")
            return
        }
        guard pinned[frame.sender] != nil else {
            drops.append("\(name): no contact for \(frame.sender.prefix(8))…")
            return
        }

        if frame.t == .initiate {
            // An `init` proves nothing about who sent it: every value in one is
            // public. Held, not opened, until the sender answers a challenge.
            if !proven.contains(frame.sender) {
                try challenge(frame, aad: aad)
                return
            }
            // PROTO-1. An init BUILDS a session only when there is none. The
            // initiator attaches the init header to every frame until it hears
            // back, so a burst sent before we reply is entirely typed `init` —
            // and handing the second one to `openInit` asks `startAsResponder`
            // to re-derive from a one-time prekey the first one already
            // consumed. It returns nil and the message inside is thrown away.
            //
            // The header is what gets ignored, not the frame. The payload is an
            // ordinary message on the sender's chain, so it goes to
            // `openMessage` and opens against the session already held — which
            // is what ConversationRouter does on `.ignoreReplay`, and what this
            // file is meant to mirror.
            if sessions[frame.sender] != nil {
                try openMessage(frame, aad: aad)
                return
            }
            try openInit(frame, aad: aad)
            return
        }
        try openMessage(frame, aad: aad)
    }

    // MARK: - The handshake (mirrors ConversationRouter)

    private func challenge(_ frame: ConversationFrame, aad: Data) throws {
        guard let senderPk = frame.senderPk else { return }
        let nonce = Handshake.nonce()
        let enc = try kem.encapsulate(senderPk)
        guard let expected = Handshake.proof(ss: enc.ss, nonce: nonce,
                                             challenger: id, prover: frame.sender),
              let bytes = Handshake.encode(.init(kind: .challenge, from: id, to: frame.sender,
                                                 nonce: nonce, ct: enc.ct, proof: nil))
        else { throw HarnessError.failed("\(name): could not build a challenge") }

        pendingChallenges[frame.sender] = PendingChallenge(nonce: nonce, expected: expected,
                                                           heldInit: (frame, aad))
        try bus.publish(bytes, to: MQTTTopics.handshake(id, frame.sender), from: id)
        handshakeEvents.append("\(name) challenged \(frame.sender.prefix(8))… and held their init")
    }

    private func handleHandshake(_ packet: BusPacket) throws {
        guard let frame = Handshake.decode(packet.payload) else { return }
        guard frame.to == id, frame.from != id else { return }
        guard packet.topic == MQTTTopics.handshake(id, frame.from) else { return }

        switch frame.kind {
        case .challenge:
            // Answer ONLY a challenge for a handshake we started — otherwise
            // this is a standing HKDF-of-a-decapsulation service.
            guard sessions[frame.from]?.pendingInit != nil, let ct = frame.ct else { return }
            let ss = try kem.decapsulate(sk: identitySk, ct: ct)
            guard let proof = Handshake.proof(ss: ss, nonce: frame.nonce,
                                              challenger: frame.from, prover: id),
                  let bytes = Handshake.encode(.init(kind: .proof, from: id, to: frame.from,
                                                     nonce: frame.nonce, ct: nil, proof: proof))
            else { return }
            try bus.publish(bytes, to: MQTTTopics.handshake(id, frame.from), from: id)
            handshakeEvents.append("\(name) proved possession to \(frame.from.prefix(8))…")

        case .proof:
            guard let pending = pendingChallenges[frame.from], let offered = frame.proof,
                  pending.nonce == frame.nonce else { return }
            guard Handshake.proofMatches(expected: pending.expected, offered: offered) else {
                handshakeEvents.append("\(name): \(frame.from.prefix(8))… FAILED the handshake")
                drops.append("\(name): handshake failed for \(frame.from.prefix(8))… — init discarded")
                pendingChallenges.removeValue(forKey: frame.from)
                return
            }
            pendingChallenges.removeValue(forKey: frame.from)
            proven.insert(frame.from)
            handshakeEvents.append("\(name): \(frame.from.prefix(8))… proved possession")
            try openInit(pending.heldInit.frame, aad: pending.heldInit.aad)
        }
    }

    // MARK: - Opening

    private func openInit(_ frame: ConversationFrame, aad: Data) throws {
        guard let ctId = frame.ctId, let ctMt = frame.ctMt, let rk = frame.rk else {
            drops.append("\(name): malformed init header"); return
        }
        let secrets = PrekeySecrets(identitySk: identitySk, mediumSk: mediumSk,
                                    oneTimeSk: { [weak self] otId in self?.oneTimeSk[otId] })
        let header = RatchetInitHeader(ctId: ctId, ctMt: ctMt, ctOt: frame.ctOt,
                                       otId: frame.ctOt == nil ? nil : frame.otId,
                                       rk: rk, cid: frame.cid)
        guard var session = RatchetSession.startAsResponder(kem: kem, secrets: secrets,
                                                            header: header) else {
            drops.append("\(name): could not derive a session from the init"); return
        }
        guard let text = open(&session, frame, aad: aad) else {
            drops.append("\(name): the init did not decrypt"); return
        }
        sessions[frame.sender] = session
        oneTimeSk.removeValue(forKey: frame.otId ?? -1)   // a one-time key is spent
        inbox.append((from: frame.sender, text: text, msgId: frame.msgId))
    }

    private func openMessage(_ frame: ConversationFrame, aad: Data) throws {
        guard var session = sessions[frame.sender] else {
            drops.append("\(name): no session with \(frame.sender.prefix(8))…"); return
        }
        guard let text = open(&session, frame, aad: aad) else {
            // A replay, a straggler, a gap too large, or a payload that did not
            // authenticate. `open` commits nothing until the tag verifies, so
            // there is nothing to write back.
            drops.append("\(name): no key for \(frame.sender.prefix(8))… n=\(frame.n)")
            return
        }
        sessions[frame.sender] = session
        inbox.append((from: frame.sender, text: text, msgId: frame.msgId))
    }

    /// The AEAD open IS the verifier: the ratchet commits nothing until it says
    /// yes. This is the shape that closed the forged-step hole.
    private func open(_ session: inout RatchetSessionState,
                      _ frame: ConversationFrame, aad: Data) -> String? {
        var plaintext: String?
        let header = RatchetHeader(cid: frame.cid, rk: frame.rk, kemCt: frame.kemCt,
                                   n: frame.n, pn: frame.pn)
        let opened = RatchetSession.open(kem: kem, state: &session, header: header) { mk in
            guard let text = try? AESService.decryptRaw(ciphertext: frame.payload,
                                                        key: SymmetricKey(data: mk), aad: aad)
            else { return false }
            plaintext = text
            return true
        }
        return opened == nil ? nil : plaintext
    }
}

enum HarnessError: Error, CustomStringConvertible {
    case failed(String)
    var description: String { if case .failed(let m) = self { return m }; return "failed" }
}
