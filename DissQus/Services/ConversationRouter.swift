import Foundation
import SwiftData
import CryptoKit

/// Debug-only logging. Compiled out of Release builds so plaintext messages,
/// seeds, keys and payloads never reach production logs (Security audit M2).
fileprivate func dlog(_ message: @autoclosure () -> String) {
    #if DEBUG
    Swift.print(message())
    #endif
}

/// Applies inbound conversation payloads to the local store: decrypt + persist a
/// message, or advance the key agreement. This is the surviving half of the old
/// `MessageHandlers`, now speaking the v2 protocol (RatchetSession /
/// AESService / HQCService are untouched); what changed is that friends are
/// resolved by CLIENT ID and that replies go out over MQTT instead of `/ws`.
@MainActor
final class ConversationRouter {

    private let modelContext: ModelContext
    private let profileManager: ProfileManager?
    /// Publishes a reply on the conversation topic (injected by ChatSession, so
    /// the router has no opinion about transport).
    private let publish: (Friend, ConversationFrame) -> Void
    /// Publishes a challenge or proof on the handshake topic. Injected for the
    /// same reason `publish` is: the router has no opinion about transport.
    private let publishHandshake: (Data, Friend) -> Void
    /// Re-send everything outgoing on a contact after yielding a simultaneous
    /// start. Injected, so the router still has no opinion about transport.
    private let resendUnconfirmed: (Friend) async -> Void
    /// Pull the friend graph again, when a frame names somebody we do not know.
    private let resyncDirectory: () async -> Void
    /// Our own published prekeys — the secrets that open an inbound `init`.
    private let prekeys: PrekeyService?
    private let kem: RatchetKem

    init(modelContext: ModelContext,
         profileManager: ProfileManager?,
         prekeys: PrekeyService?,
         kem: RatchetKem = HQCKem(),
         publish: @escaping (Friend, ConversationFrame) -> Void,
         publishHandshake: @escaping (Data, Friend) -> Void = { _, _ in },
         resendUnconfirmed: @escaping (Friend) async -> Void = { _ in },
         resyncDirectory: @escaping () async -> Void = {}) {
        self.modelContext = modelContext
        self.profileManager = profileManager
        self.prekeys = prekeys
        self.kem = kem
        self.publish = publish
        self.publishHandshake = publishHandshake
        self.resendUnconfirmed = resendUnconfirmed
        self.resyncDirectory = resyncDirectory
    }

    private var currentProfile: Profile? { profileManager?.currentProfile }
    private var myID: String { currentProfile?.peerID ?? "" }

    /// Read the profile's private key for an INBOUND frame.
    ///
    /// Opens the key-burst window first. `init` is the only frame that needs
    /// the identity key, and they arrive in bursts — several contacts opening
    /// sessions when a device comes back online.
    /// Without this each one was a separate Face ID, because the window was only
    /// ever opened by sign-in and profile switch, and anything landing more than
    /// 20s later missed it. `beginKeyBurstUnlock` will not extend a window that
    /// is already open, so the peer cannot lengthen how long we hold the key.
    private func getSecretKey(reason: String) -> Data? {
        guard let profileManager else { return IdentityManager.getSecretKey() }
        profileManager.beginKeyBurstUnlock()
        return profileManager.getSecretKey(reason: reason)
    }

    /// Friend lookup by client id, scoped to the active profile.
    ///
    /// A direct match on the id the envelope's `sender` carries — no username
    /// indirection, and nothing to spoof. It compared `Data` against the pinned
    /// public key before; the id is what the wire carries now, and (unlike a
    /// username) it is a commitment to that same key.
    func friend(withID id: String) -> Friend? {
        guard let profileId = currentProfile?.id, !id.isEmpty else { return nil }
        let descriptor = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.peerID == id && $0.profile?.id == profileId }
        )
        return try? modelContext.fetch(descriptor).first
    }

    /// Senders we have already resynced the directory for, so a frame we still
    /// cannot place does not re-poll on every retry.
    private var resyncedFor: Set<String> = []

    /// Find the contact this frame is from, resyncing the directory once if we
    /// have never heard of them.
    ///
    /// An invite is sent to a HANDLE, so the inviter's contact row carries an
    /// empty `peerID` until a directory sync fills it in — and the sync is a
    /// 60-second poll, because nothing pushes graph changes. The invitee now
    /// greets the moment they accept, so their `init` routinely arrives at the
    /// inviter BEFORE the inviter knows their client id. The lookup missed, the
    /// frame was dropped, and nothing retried it.
    ///
    /// What made it look like a protocol fault rather than a race: the greeting
    /// only appeared once the inviter sent something of their own. That send
    /// opened a second session, which collided with the one already waiting, and
    /// the collision handling re-sent the greeting. So the message did arrive —
    /// but only as a side effect of the recipient speaking first, which is the
    /// exact thing the greeting exists to spare them.
    ///
    /// Resyncing is safe rather than an invitation to poll on demand: the broker
    /// grants `publish` on our inbox to FRIENDS only, so a frame we cannot place
    /// is from someone the server already considers a contact and we simply have
    /// not learned about yet. That is precisely what a resync fixes.
    private func friendResolving(_ id: String) async -> Friend? {
        if let known = friend(withID: id) { return known }
        guard !id.isEmpty, !resyncedFor.contains(id) else { return nil }
        resyncedFor.insert(id)
        dlog("[ConversationRouter] · frame from an unknown \(id.prefix(8))… — resyncing the directory")
        ProtocolLog.record(.directoryResyncedForUnknownSender(peer: id))
        await resyncDirectory()
        return friend(withID: id)
    }

    // MARK: - Proving an `init` came from the peer it names
    //
    // An `init` is derived entirely from PUBLIC values: the responder's prekey
    // bundle is published for anyone to claim, and `senderPk` is fetchable
    // without a session at all. So any accepted friend can produce one that
    // names a third party and authenticates perfectly — which is exactly what
    // was reproduced, and the reason a session is no longer opened from an
    // `init` alone.
    //
    // A KEM cannot fix that in one flight: encapsulation demonstrates the
    // RECIPIENT's secret, never the sender's. So the initiator has to receive
    // something first, and what it receives is an ordinary HQC encapsulation to
    // its identity key. See Handshake.swift.

    /// How long a challenge stands. A peer that cannot answer in this window has
    /// its `init` dropped; the initiator carries `pendingInit` on every frame,
    /// so the next thing they send starts a fresh exchange.
    private static let handshakeTTL: TimeInterval = 60

    private struct PendingChallenge {
        let nonce: Data
        let expected: Data
        /// The `init` being held until the proof lands, with the AAD it opens
        /// against — rebuilding that later is exactly the mistake v3 removed.
        let heldInit: (frame: ConversationFrame, aad: Data)
        let expiresAt: Date
    }

    /// Challenges we have issued and are waiting on, keyed by the peer's id.
    private var pendingChallenges: [String: PendingChallenge] = [:]
    /// Peers that have proven possession of their identity key this launch.
    private var proven: Set<String> = []

    private func sweepChallenges(_ now: Date = Date()) {
        for (peer, c) in pendingChallenges where c.expiresAt <= now {
            pendingChallenges.removeValue(forKey: peer)
            dlog("[ConversationRouter] · handshake with \(peer.prefix(8))… timed out — init dropped")
        }
    }

    /// Challenge the sender of an `init` to prove it holds the key it claims.
    ///
    /// The key we encapsulate to comes from the frame itself, which is safe for
    /// the one reason that matters: the decoder has already refused any `init`
    /// whose `senderPk` does not hash to its `sender`. So it IS that peer's real
    /// key — the commitment doing its job — and only that peer can decapsulate.
    private func challengeInitiator(_ friend: Friend, _ envelope: ConversationFrame, aad: Data) {
        guard let senderPk = envelope.senderPk else { return }
        sweepChallenges()

        let nonce = Handshake.nonce()
        guard let enc = try? kem.encapsulate(senderPk),
              let expected = Handshake.proof(ss: enc.ss, nonce: nonce,
                                             challenger: myID, prover: friend.peerID),
              let frame = Handshake.encode(.init(kind: .challenge, from: myID, to: friend.peerID,
                                                 nonce: nonce, ct: enc.ct, proof: nil))
        else {
            dlog("[ConversationRouter] ❌ could not build a challenge for \(friend.username)")
            return
        }
        pendingChallenges[friend.peerID] = PendingChallenge(
            nonce: nonce, expected: expected, heldInit: (envelope, aad),
            expiresAt: Date().addingTimeInterval(Self.handshakeTTL)
        )
        publishHandshake(frame, friend)
        ProtocolLog.record(.handshakeChallenged(peer: friend.peerID))
        dlog("[ConversationRouter] 🔐 challenged \(friend.username) — holding their init")
    }

    /// A challenge or a proof arrived on `h/{friendshipHash}`.
    func handleHandshake(_ raw: Data, topic: String) async {
        guard let frame = Handshake.decode(raw) else { return }
        guard !myID.isEmpty, frame.to == myID, frame.from != myID else { return }
        // The topic is derived from the two ids, so a frame claiming to be from
        // a peer must arrive on the topic that peer's id builds — the same rule
        // `handle` applies to conversation frames.
        guard topic == MQTTTopics.handshake(myID, frame.from) else { return }
        guard let friend = friend(withID: frame.from), !friend.isVanished else { return }

        switch frame.kind {
        case .challenge:
            // Answer ONLY a challenge for a handshake we started. Otherwise this
            // is a standing HKDF-of-a-decapsulation service for anyone who can
            // reach the topic — harmless in itself, since implicit rejection
            // means a forged ciphertext yields a pseudo-random secret, but there
            // is no reason to offer it.
            guard friend.ratchetSession?.pendingInit != nil, let ct = frame.ct else { return }
            guard let sk = getSecretKey(reason: "proving your identity to \(friend.username)"),
                  let ss = try? kem.decapsulate(sk: sk, ct: ct),
                  let proof = Handshake.proof(ss: ss, nonce: frame.nonce,
                                              challenger: frame.from, prover: myID),
                  let reply = Handshake.encode(.init(kind: .proof, from: myID, to: frame.from,
                                                     nonce: frame.nonce, ct: nil, proof: proof))
            else { return }
            publishHandshake(reply, friend)
            ProtocolLog.record(.handshakeProved(peer: frame.from))
            dlog("[ConversationRouter] 🔐 proved our identity to \(friend.username)")

        case .proof:
            sweepChallenges()
            guard let pending = pendingChallenges[frame.from],
                  let offered = frame.proof,
                  pending.nonce == frame.nonce else { return }
            guard Handshake.proofMatches(expected: pending.expected, offered: offered) else {
                // Not a transport failure. Somebody sent an `init` naming this
                // peer and could not prove they hold its key — the attack,
                // arriving.
                dlog("[ConversationRouter] ❌ \(friend.username) FAILED the handshake — init discarded")
                ProtocolLog.record(.handshakeFailed(peer: frame.from))
                pendingChallenges.removeValue(forKey: frame.from)
                return
            }
            pendingChallenges.removeValue(forKey: frame.from)
            proven.insert(frame.from)
            ProtocolLog.record(.handshakeProven(peer: frame.from))
            dlog("[ConversationRouter] ✅ \(friend.username) proved possession — opening their init")
            await handleInit(from: friend, pending.heldInit.frame, aad: pending.heldInit.aad)
        }
    }

    // MARK: - Inbound

    /// - Parameters:
    ///   - aad: the bytes this frame's payload was sealed against. Handed in
    ///     rather than rebuilt: on v3 it is the literal byte range that arrived,
    ///     because the header is the frame's own prefix.
    ///   - topic: the MQTT topic the frame arrived on. Not decoration — see the
    ///     entitlement check below.
    func handle(_ envelope: ConversationFrame, aad: Data, topic: String) async {
        // Our own publish comes back to us (MQTT delivers to every subscriber of
        // the topic, publisher included). Nothing to do with it.
        guard let myID = currentProfile?.peerID, !myID.isEmpty else { return }
        if envelope.sender == myID { return }

        // A frame must arrive where that sender is ENTITLED to put it: an `init`
        // on our own inbox, anything else on the conversation topic the two ids
        // derive. Without this a frame is attributed by `envelope.sender` alone,
        // so any friend — and everyone is auto-friended to the helper bot — can
        // publish a `msg` naming a third party into a topic they do share, and
        // have it dispatched into that third party's session.
        //
        // Checked BEFORE `friendResolving`, deliberately: resolving an unknown
        // sender triggers a directory resync, and a frame that had no business
        // being here must not be able to spend that.
        //
        // bot.ts has enforced exactly this since it was written (onEnvelope);
        // this is the client catching up.
        // A frame says who it was FOR, and says it inside the AAD, so one
        // addressed to somebody else cannot be re-aimed at us without breaking
        // the tag — whatever carried it.
        //
        // This was `if let to = envelope.to`, because a v2 frame had no
        // recipient field and the binding failed, which SKIPPED the check and
        // left the topic check below as the only answer. Unconditional now, and
        // strictly stronger: every frame is checked. The topic check stays as
        // defence in depth — it is cheap, and it caught a real bug.
        if envelope.to != myID {
            dlog("[ConversationRouter] ❌ frame addressed to \(envelope.to.prefix(8))… — not ours")
            ProtocolLog.record(.dropped(stage: "recipient", peerID: envelope.sender,
                                        reason: "the frame names a different recipient"))
            return
        }

        let expected = MQTTTopics.expected(forInit: envelope.t == .initiate,
                                           sender: envelope.sender, me: myID)
        guard topic == expected else {
            dlog("[ConversationRouter] ❌ \(kindName(envelope)) from "
                 + "\(envelope.sender.prefix(8))… arrived on \(MQTTTopics.describe(topic)) — dropped")
            ProtocolLog.record(.dropped(stage: "topic-binding", peerID: envelope.sender,
                                        reason: "a \(kindName(envelope)) from this sender may only arrive on \(MQTTTopics.describe(expected))"))
            return
        }

        guard let friend = await friendResolving(envelope.sender) else {
            dlog("[ConversationRouter] ❌ no contact for \(envelope.sender.prefix(16))…")
            ProtocolLog.record(.dropped(stage: "envelope", peerID: envelope.sender,
                                        reason: "no contact row for this sender, even after a directory resync"))
            return
        }
        // A vanished identity cannot send: its id is gone from the server, so
        // nothing should be arriving under it. If something does, it is not the
        // contact this row represents.
        if friend.isVanished {
            dlog("[ConversationRouter] ❌ frame for a vanished identity (\(friend.username)) — dropped")
            ProtocolLog.record(.dropped(stage: "envelope", peerID: friend.peerID,
                                        reason: "vanished identity — the server no longer lists this id"))
            return
        }
        switch envelope.t {
        case .initiate:
            ProtocolLog.record(.initReceived(from: friend.peerID,
                                             hasSenderPk: envelope.senderPk != nil))
            // An `init` proves nothing about who sent it — every value in one is
            // public. So it is HELD, not opened, until the sender answers a
            // challenge. `proven` is per-launch: a restart re-challenges, which
            // costs one round trip and is the safe direction to be wrong in.
            if !proven.contains(friend.peerID) {
                challengeInitiator(friend, envelope, aad: aad)
                return
            }
            await handleInit(from: friend, envelope, aad: aad)
        case .message:
            await handleMsg(from: friend, envelope, aad: aad)
        }
    }

    /// Open a session from an inbound `init`.
    ///
    /// One frame does what v1's `aes` offer/answer pair did across a live round
    /// trip — and it carries a real message, so a conversation can begin while
    /// this device was offline. The whole offer-backoff and re-offer machinery
    /// that existed to heal a half-finished exchange has no counterpart here:
    /// there is no half-finished state to be in.
    private func handleInit(from friend: Friend, _ envelope: ConversationFrame, aad: Data) async {
        dlog("[ConversationRouter] 🤝 init ← \(friend.username)")
        /// Whether we reached the responder path by giving up our own session.
        var wasGlare = false

        // A session already running is NOT replaced by an inbound init. That is
        // the difference between "my peer reinstalled" and "somebody replayed a
        // frame to wipe my conversation", and only the user can tell them apart.
        // (A peer who really did reinstall has a NEW key, hence a new id, hence
        // a new contact — see DirectorySync's vanished-identity handling. They
        // could not reach this row at all.)
        if friend.hasSession {
            // Two cases hide behind "we already have a session", and they need
            // opposite answers.
            //
            // ESTABLISHED — we have heard from them, so they demonstrably hold
            // our session. An init now is a replay, and honouring it would let
            // anyone wipe a conversation by re-sending an old frame. Ignore.
            //
            // GLARE — `pendingInit` is still set, which means they have never
            // sent us anything, which means they cannot hold our session. Both
            // sides started at once. Ignoring here is what lost the greeting:
            // each device kept its own initiator session, threw away the other's
            // init AND the message inside it, and every later frame decrypted
            // against a session the peer had never heard of. The conversation
            // was dead in both directions from its first second.
            //
            // Simultaneous starts became common the moment accepting an invite
            // began sending a greeting on the user's behalf: before that a
            // session opened only when a human typed, so two people racing was
            // rare. Mutual invites now produce it every time.
            guard let myID = currentProfile?.peerID, !myID.isEmpty else { return }
            switch InitCollision.resolve(hasSession: true,
                                         heardFromThem: friend.ratchetSession?.pendingInit == nil,
                                         myID: myID, peerID: friend.peerID) {
            case .open:
                break
            case .ignoreReplay:
                // The init HEADER is ignored — the session is not replaced, for
                // the reason above. The frame is NOT.
                //
                // PROTO-1. `pendingInit` rides every frame an initiator sends
                // until they hear back from us, so a peer who sends "hi", "you
                // there?", "it's about tomorrow" before we have replied sends
                // three frames all typed `.initiate`. Returning here threw away
                // the messages inside the second and third — measured on the
                // server implementation of the same rule as two losses in three,
                // against a real broker, before the pair of them were fixed
                // together.
                //
                // `handleMsg` opens the payload against the session we already
                // hold, which is exactly what it is: an ordinary message on the
                // sender's chain. Every protection stays — `open` commits
                // nothing until the tag verifies, and a re-entered chain is
                // still refused — because we never re-root from the header.
                dlog("[ConversationRouter] · init from \(friend.username) — session already open, opening its payload as a message")
                ProtocolLog.record(.initIgnoredSessionOpen(peer: friend.peerID))
                await handleMsg(from: friend, envelope, aad: aad)
                return
            case .keepOurs:
                dlog("[ConversationRouter] · simultaneous init from \(friend.username) — keeping ours (lower id)")
                ProtocolLog.record(.initGlareKept(peer: friend.peerID))
                return
            case .yieldToTheirs:
                // Nothing of ours reached them: they ignored our init for the
                // same reason we nearly ignored theirs, so every message we have
                // sent on this contact is unreceived. `resendUnconfirmed` puts
                // them back on the surviving session once it is open.
                dlog("[ConversationRouter] · simultaneous init from \(friend.username) — yielding to theirs")
                ProtocolLog.record(.initGlareYielded(peer: friend.peerID))
                friend.ratchetSession = nil
                wasGlare = true
            }
        }

        // The initiator's key rode on the frame. `isWellFormed` has already
        // refused any `init` whose `senderPk` does not hash to its `sender`, so
        // by the time this runs the key is known to be the one this contact's id
        // names — `pin` re-checks anyway, because the one place a key is written
        // is the one place that check belongs.
        // Bytes on the wire in v3, hex in v2 — and hex is what `pin` and
        // `PeerID.matches` hash, so hex is what the store keeps either way.
        if let senderPk = envelope.senderPk.map({ $0.map { String(format: "%02x", $0) }.joined() }),
           !friend.hasPinnedKey {
            if friend.pin(publicKeyHex: senderPk) {
                dlog("[ConversationRouter] 🔑 pinned \(friend.username)'s key from their init")
                ProtocolLog.record(.keyPinned(peer: friend.peerID, source: .initFrame))
            } else {
                ProtocolLog.record(.keyRejected(peer: friend.peerID,
                                                reason: "senderPk does not hash to sender"))
            }
        }

        guard let secretKey = getSecretKey(reason: "opening a session with \(friend.username)") else {
            dlog("[ConversationRouter] ❌ init from \(friend.username) dropped — "
                 + "could not read the private key (unlock dismissed or unavailable)")
            ProtocolLog.record(.dropped(stage: "init", peerID: friend.peerID,
                                        reason: "identity key unreadable (unlock dismissed?)"))
            return
        }
        guard let prekeys, let secrets = prekeys.secrets(identitySk: secretKey) else {
            dlog("[ConversationRouter] ❌ init from \(friend.username) dropped — "
                 + "this profile has published no prekeys yet")
            ProtocolLog.record(.dropped(stage: "init", peerID: friend.peerID,
                                        reason: "this profile has published no prekeys"))
            return
        }
        guard let header = Self.initHeader(from: envelope) else {
            dlog("[ConversationRouter] ❌ init from \(friend.username) dropped — malformed header")
            ProtocolLog.record(.dropped(stage: "init", peerID: friend.peerID,
                                        reason: "malformed init header"))
            return
        }

        guard var session = RatchetSession.startAsResponder(kem: kem, secrets: secrets, header: header) else {
            // A one-time secret we no longer hold, or a ciphertext that is not
            // ours. Both are ordinary — a duplicate init, or a frame built on a
            // key already consumed — and neither is worth alarming the user over.
            dlog("[ConversationRouter] ❌ could not derive a session from \(friend.username)'s init")
            ProtocolLog.record(.dropped(stage: "init", peerID: friend.peerID,
                                        reason: "one-time secret already consumed, or not our ciphertext"))
            return
        }

        // Open the message the init carried BEFORE burning the one-time key, so
        // a frame that turns out to be undecryptable does not cost us the key.
        guard let text = Self.openFrame(kem: kem, session: &session, envelope, aad: aad) else {
            dlog("[ConversationRouter] ❌ init from \(friend.username) did not decrypt")
            ProtocolLog.record(.dropped(stage: "init", peerID: friend.peerID,
                                        reason: "session derived but the payload did not decrypt"))
            return
        }

        let yielded = friend.ratchetSession == nil && wasGlare
        friend.ratchetSession = session
        if let otId = envelope.otId { prekeys.consumeOneTime(id: otId) }
        store(text, from: friend, msgId: envelope.msgId)
        dlog("[ConversationRouter] ✅ session open with \(friend.username)")
        ProtocolLog.record(.sessionOpenedAsResponder(peer: friend.peerID,
                                                     usedOneTime: envelope.otId != nil))
        // Only after the session is in place, or the resend would open a second
        // one and start the race again.
        if yielded { await resendUnconfirmed(friend) }
    }

    /// Decrypt and store a text message.
    ///
    /// Every message is ratcheted — there is no static-key path to fall back to
    /// any more, which is what closes KM-5. The header is bound as AAD, so a
    /// tampered `cid`/`n`/`rk` produces no message rather than a wrong one.
    private func handleMsg(from friend: Friend, _ envelope: ConversationFrame, aad: Data) async {
        guard var session = friend.ratchetSession else {
            dlog("[ConversationRouter] ❌ no session with \(friend.username)")
            ProtocolLog.record(.messageUndecryptable(peer: friend.peerID,
                                                     reason: "no session — their init never arrived"))
            return
        }
        guard let text = Self.openFrame(kem: kem, session: &session, envelope, aad: aad) else {
            // A replay, a straggler from a retired chain, a gap too large to
            // bridge, or a frame that did not authenticate. All ordinary, and
            // none of them has changed the session: `open` commits nothing until
            // the tag verifies, so there is nothing here to write back.
            //
            // Writing it back is what the old code did, and it is how one forged
            // ratchet step destroyed a conversation for good — `open` had already
            // replaced the root and adopted the sender's key by the time the tag
            // failed, and this line persisted it.
            dlog("[ConversationRouter] · no key for \(friend.username) frame "
                 + "(cid \(envelope.cid.prefix(8))…, n \(envelope.n))")
            ProtocolLog.record(.messageUndecryptable(peer: friend.peerID,
                                                     reason: "no key for this position (replay, retired chain, too large a gap, or a payload that did not authenticate)"))
            return
        }

        friend.ratchetSession = session
        store(text, from: friend, msgId: envelope.msgId)
        ProtocolLog.record(.messageDecrypted(peer: friend.peerID))
    }

    /// Persist a decrypted message and refresh the badges.
    ///
    /// `msgId` is the frame's own identifier, bound as AAD on every message and
    /// — until now — read by absolutely nothing. It was the one field in the
    /// protocol that cost bytes on every frame and bought nothing.
    ///
    /// What it buys here is deduplication at the APPLICATION layer, independent
    /// of the ratchet. The ratchet already refuses a frame at a position it has
    /// consumed, so a plain redelivery is caught — but that is a statement about
    /// chain positions, not about messages. A peer that re-sends the same text
    /// after a failed publish seals it at a NEW position, which decrypts
    /// perfectly and would be stored a second time. `ChatSession.resend` does
    /// exactly that, reusing the stored `messageId`, which is what makes this
    /// check land.
    private func store(_ text: String, from friend: Friend, msgId: String) {
        if !msgId.isEmpty, alreadyStored(msgId: msgId, from: friend) {
            dlog("[ConversationRouter] · duplicate \(msgId.prefix(8))… from \(friend.username) — not stored twice")
            return
        }
        let message = Message(content: text, isOutgoing: false, friend: friend,
                              messageId: msgId.isEmpty ? nil : msgId)
        modelContext.insert(message)
        try? modelContext.save()

        NotificationService.shared.notifyMessage(from: friend.username)
        NotificationService.shared.refreshCounts(modelContext: modelContext,
                                                profileID: currentProfile?.id)
    }

    /// Open one inbound frame: the ratchet offers a candidate key, the AEAD decides.
    ///
    /// The two are one call because the tag is the ONLY authenticator this
    /// protocol has — HQC decapsulation returns a pseudo-random secret for a
    /// forged ciphertext rather than failing, so nothing before the tag check has
    /// established anything at all. Passing the decrypt in as the verifier is
    /// what keeps a fabricated ratchet step from mutating `session` before
    /// something has vouched for it; see the note on `RatchetSession.open`.
    ///
    /// `session` is left EXACTLY as it was found whenever this returns nil, so a
    /// caller has nothing to persist on a refusal.
    private static func openFrame(kem: RatchetKem,
                                  session: inout RatchetSessionState,
                                  _ envelope: ConversationFrame,
                                  aad: Data) -> String? {
        var plaintext: String?
        let opened = RatchetSession.open(kem: kem, state: &session,
                                         header: Self.messageHeader(from: envelope)) { mk in
            guard let text = try? AESService.decryptRaw(ciphertext: envelope.payload,
                                                        key: SymmetricKey(data: mk), aad: aad) else {
                return false
            }
            plaintext = text
            return true
        }
        return opened == nil ? nil : plaintext
    }

    /// Whether this exact frame has already been stored for this contact.
    ///
    /// Scoped to the CONTACT as well as the id: `msgId` is chosen by the sender,
    /// so it is unique only within one peer's frames. Two contacts colliding on
    /// a UUID would otherwise silently swallow one of the two messages.
    private func alreadyStored(msgId: String, from friend: Friend) -> Bool {
        let peerID = friend.peerID
        guard !peerID.isEmpty else { return false }
        var descriptor = FetchDescriptor<Message>(
            predicate: #Predicate<Message> { $0.messageId == msgId && $0.friend?.peerID == peerID }
        )
        descriptor.fetchLimit = 1
        return ((try? modelContext.fetch(descriptor))?.isEmpty == false)
    }

    // MARK: - Header adapters
    //
    // The wire envelope carries base64; the ratchet works in bytes. Keeping the
    // conversion here means neither the state machine nor the envelope has to
    // know about the other.

    private static func messageHeader(from e: ConversationFrame) -> RatchetHeader {
        RatchetHeader(cid: e.cid, rk: e.rk, kemCt: e.kemCt, n: e.n, pn: e.pn)
    }

    /// The frame kind, for a log line. `ConversationFrame.Kind` has no raw value
    /// — the two wire formats spell it differently (a JSON string, a byte) and
    /// neither spelling belongs in a message a human reads.
    private func kindName(_ e: ConversationFrame) -> String {
        e.t == .initiate ? "init" : "msg"
    }

    private static func initHeader(from e: ConversationFrame) -> RatchetInitHeader? {
        guard let ctId = e.ctId, let ctMt = e.ctMt, let rk = e.rk else { return nil }
        // ctOt and otId travel together or not at all — `parseEnvelope`/
        // `isWellFormed` already rejected the mismatched case, so a nil here is
        // the exhausted-pool path rather than a malformed frame.
        let ctOt = e.ctOt
        return RatchetInitHeader(ctId: ctId, ctMt: ctMt, ctOt: ctOt,
                                 otId: ctOt == nil ? nil : e.otId,
                                 rk: rk, cid: e.cid)
    }

    // MARK: - Presence

    /// A friend's retained presence flipped (MQTT `u/{id}/presence`).
    func setPresence(id: String, online: Bool) {
        guard let friend = friend(withID: id) else { return }
        friend.isOnline = online
        try? modelContext.save()
    }

    /// Everyone goes dark when our own connection drops — otherwise the roster
    /// keeps showing the state from the moment the link died.
    func clearAllPresence() {
        guard let profileId = currentProfile?.id else { return }
        let descriptor = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.profile?.id == profileId && $0.isOnline }
        )
        guard let friends = try? modelContext.fetch(descriptor) else { return }
        for friend in friends { friend.isOnline = false }
        try? modelContext.save()
    }
}
