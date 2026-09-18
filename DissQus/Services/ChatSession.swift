import Foundation
import CryptoKit
import SwiftData

fileprivate func dlog(_ message: @autoclosure () -> String) {
    #if DEBUG
    Swift.print(message())
    #endif
}

/// The client's connection to the server, in one place — and the replacement for
/// `WebSocketManager` + the transport half of `MessageHandlers` (Phase 4 of the
/// MQTT migration; see deploy/EXTRACTION_PLAN.md).
///
/// V0 speaks exactly two protocols and no custom one:
///
///   * **REST** (`AuthService` + `APIClient`) — the HQC-KEM handshake, tokens,
///     the friend graph, usernames, push registration, account deletion.
///   * **MQTT over WSS** (`MQTTService`) — messages and presence, and nothing
///     else. No call signalling, no media: those come back in later phases, over
///     MQTT control topics, not over a bespoke socket.
///
/// Two consequences worth stating, because they are what the old `/ws` design
/// hid: the server is no longer in the message path (EMQX fans out ciphertext it
/// cannot read, and the offline queue is the broker's QoS-1 session), and the
/// client is no longer told about graph changes — it asks (see `DirectorySync`).
@MainActor
final class ChatSession: ObservableObject {

    /// Authentication + MQTT link state, in the order they happen.
    enum State: Equatable {
        case idle
        case authenticating     // REST handshake (this is what needs the key)
        case connecting         // handshake done, MQTT dialling
        case connected          // CONNACK; messages flow
    }

    @Published private(set) var state: State = .idle

    let auth = AuthService()
    let api: APIClient
    private let mqtt: MQTTService
    private let backend = MQTTWireClient()

    private var modelContext: ModelContext?
    private var profileManager: ProfileManager?
    private var router: ConversationRouter?
    private var directory: DirectorySync?
    /// Our own published prekeys — what lets peers open a session with us while
    /// this device is offline.
    private var prekeys: PrekeyService?
    /// The KEM the ratchet rides on. A stored property rather than a call to
    /// `HQCKem()` at each use, so a test can substitute a stub.
    private let kem: RatchetKem = HQCKem()

    /// Raised when the link drops unexpectedly; AppState owns the backoff loop.
    var onDisconnect: (() -> Void)?
    /// Raised once per successful login+connect.
    var onConnected: (() -> Void)?
    /// The server will not serve this key at all — a private (`allowlist`)
    /// deployment. It is the only refusal left: there is no paywall to be on
    /// the wrong side of.
    var onNotAdmitted: (() -> Void)?
    /// The private key could not be read — a dismissed or failed unlock.
    var onUnlockFailed: (() -> Void)?

    init() {
        let auth = self.auth
        self.api = APIClient(auth: auth)
        self.mqtt = MQTTService(backend: backend, auth: auth)
    }

    // MARK: - Wiring

    func configure(modelContext: ModelContext, profileManager: ProfileManager?) {
        self.modelContext = modelContext
        self.profileManager = profileManager
        let prekeys = PrekeyService(api: api) { [weak profileManager] in
            profileManager?.currentProfile?.id
        }
        self.prekeys = prekeys
        let router = ConversationRouter(
            modelContext: modelContext,
            profileManager: profileManager,
            prekeys: prekeys,
            publish: { [weak self] friend, envelope in self?.publish(envelope, to: friend) },
            publishHandshake: { [weak self] bytes, friend in
                self?.publishHandshake(bytes, to: friend)
            },
            resendUnconfirmed: { [weak self] friend in await self?.resendUnconfirmed(to: friend) },
            resyncDirectory: { [weak self] in _ = await self?.refreshDirectory() }
        )
        self.router = router
        self.directory = DirectorySync(api: api, modelContext: modelContext,
                                       profileManager: profileManager)

        Task {
            await mqtt.setMessageHandler { [weak self] topic, payload in
                guard let self else { return }
                // Reporting, not the plain `decode`. A refused frame used to
                // return here in silence — which is what an 82 kB `init` did on
                // every device, every time, with the whole first-contact path
                // reading as if it had worked.
                // Either version, decided by the BYTES. The AAD comes back with
                // the frame — on v3 it is the literal byte range that arrived,
                // because the header is the frame's own prefix; on v2 it has to
                // be rebuilt. Getting it from one place means no caller can pick
                // the wrong one.
                let result = ConversationFrame.decodeReporting(payload)
                guard let (frame, aad) = result.result else {
                    ProtocolLog.record(.dropped(stage: "envelope-decode", peerID: nil,
                                                reason: result.reason))
                    return
                }
                // The topic travels with the frame: the router checks that this
                // sender was entitled to publish this KIND of frame here. It
                // used to be discarded, which is what let one friend reach every
                // other session on this device.
                Task { @MainActor in await self.router?.handle(frame, aad: aad, topic: topic) }
            }
            await mqtt.setHandshakeHandler { [weak self] topic, payload in
                Task { @MainActor in await self?.router?.handleHandshake(payload, topic: topic) }
            }
            // The server pushes graph changes now, so an invite or an accept
            // lands in seconds rather than waiting on the poll below. The poll
            // stays as the floor: a nudge is best-effort, and a client that was
            // offline for one has to find out somehow.
            await mqtt.setGraphHandler { [weak self] in
                Task { @MainActor in _ = await self?.refreshDirectory() }
            }
            await mqtt.setPresenceHandler { [weak self] id, online in
                Task { @MainActor in self?.router?.setPresence(id: id, online: online) }
            }
            await mqtt.setConnectionHandler { [weak self] connected, error in
                Task { @MainActor in self?.linkChanged(connected: connected, error: error) }
            }
        }
    }

    var isConnected: Bool { state == .connected }

    // MARK: - Login

    /// Full login: REST handshake (the one moment that needs the private key),
    /// then the friend graph, then MQTT. Throws on transport/auth failure so the
    /// caller can show it and schedule a retry.
    func connect() async throws {
        guard let profile = profileManager?.currentProfile,
              let publicKey = profile.publicKey else {
            throw AuthService.AuthError.notAuthenticated
        }

        // Endpoints follow the profile's home server (nil = the build default).
        ServerConfig.activeHost = profile.serverHost

        state = .authenticating
        // One unlock window covers the handshake AND the key-agreement burst that
        // follows it, so a login costs a single Face ID rather than one per friend.
        profileManager?.beginHandshakeUnlock()
        // NOT `profileManager?.getSecretKey() ?? IdentityManager.getSecretKey()`.
        // `??` fires whenever the left side is nil — including when the user just
        // CANCELLED the prompt it raised — so a single refused sign-in raised a
        // second one immediately, from a different Keychain item, uncounted.
        // The legacy store is a fallback for having no profile manager, not for
        // being told no.
        let storedKey: Data? = profileManager == nil
            ? IdentityManager.getSecretKey(reason: "sign in (legacy identity)")
            : profileManager?.getSecretKey(reason: "sign in")
        guard let secretKey = storedKey else {
            profileManager?.endHandshakeUnlock()
            state = .idle
            onUnlockFailed?()
            throw AuthService.AuthError.notAuthenticated
        }

        do {
            // AuthService tries the full door and falls back to the free one, so
            // a 402 never reaches here. Nothing produces one any more either;
            // the fallback is kept for an out-of-date server (see AuthService).
            _ = try await auth.login(publicKeyHex: publicKey.hexString, secretKey: secretKey)
        } catch let AuthService.AuthError.badResponse(code, _) where code == 403 {
            state = .idle
            onNotAdmitted?()
            return
        }

        state = .connecting
        // The broker knows us by our CLIENT ID, not our key: it is the MQTT
        // client id, the username, and what `WHERE id = ${clientid}` matches in
        // the topic ACL.
        try await mqtt.connect(id: profile.peerID)
        // The graph is fetched in parallel with the MQTT dial; subscriptions are
        // applied when CONNACK lands (see linkChanged).
        await refreshDirectory()
    }

    /// Reconnect without a new handshake where possible: the MQTT connect token
    /// rotates off the REST session bearer, which outlives it. Only when THAT is
    /// gone do we fall back to a full login (and another unlock).
    func reconnect() async throws {
        guard let profile = profileManager?.currentProfile,
              let pk = profile.publicKey?.hexString else {
            throw AuthService.AuthError.notAuthenticated
        }
        // The bearer has to belong to THIS key, not merely exist. Both are held in
        // memory by one AuthService that outlives any single profile, so a switch
        // whose teardown did not land — the reset in AppState.initialize() is
        // skipped when the previous profile never finished connecting — leaves the
        // previous profile's session sitting here. Reusing it mints an MQTT token
        // for the PREVIOUS key, the broker refuses the CONNECT as that key is not
        // the one connecting (CONNACK 5), and `needsFreshHandshake` reads a broker
        // refusal as transport trouble rather than an authentication problem — so
        // the backoff loop re-mints the same wrong token forever, without ever
        // trying the handshake that would fix it.
        guard let session = await auth.currentSession(), session.pk == pk else {
            try await connect()
            return
        }
        state = .connecting
        do {
            try await mqtt.connect(id: profile.peerID)
            await refreshDirectory()
        } catch {
            guard Self.needsFreshHandshake(error) else {
                // A transport failure is NOT an authentication failure. This
                // catch used to treat every throw as one and re-run the full
                // handshake, which reads the private key — so an unreachable
                // broker, a timeout or a network blip each cost a Face ID. The
                // reconnect backoff calls this on every attempt, so a link that
                // stayed down prompted over and over, indefinitely, for a
                // handshake that could not have fixed it.
                dlog("[ChatSession] reconnect failed (\(error)) — transport, not auth; retrying without a handshake")
                state = .idle
                throw error
            }
            dlog("[ChatSession] session rejected (\(error)) — full re-login")
            try await connect()
        }
    }

    /// Whether a failed reconnect means our REST session is gone, as opposed to
    /// the network or the broker being unavailable.
    ///
    /// Only the first justifies spending a biometric prompt: a new handshake
    /// replaces a session the server will not accept, and does nothing whatever
    /// for a connection that never got there.
    private static func needsFreshHandshake(_ error: Error) -> Bool {
        switch error {
        case AuthService.AuthError.notAuthenticated:
            return true
        case AuthService.AuthError.badResponse(let code, _):
            // 401 = the bearer is dead. A 403 is a decision about the KEY, and
            // a fresh handshake would be refused the same way — `connect()` maps
            // it to its own state rather than looping on it.
            return code == 401
        default:
            return false
        }
    }

    func disconnect() async {
        await mqtt.disconnect()
        state = .idle
        stopDirectoryPoll()
    }

    func logout() async {
        await disconnect()
        await auth.logout()
    }

    // MARK: - Directory

    /// Pull the friend graph, subscribe to every conversation, and start key
    /// agreement with anyone we do not yet share a channel with.
    @discardableResult
    func refreshDirectory() async -> [Friend] {
        guard let directory else { return [] }
        do {
            let friends = try await directory.sync()
            let unopened = friends.filter { !$0.hasSession }
            // The graph is not pushed (see DirectorySync), so this line is the
            // only place that says what we believe the graph IS.
            dlog("[ChatSession] 📇 directory: \(friends.count) friend(s), "
                 + "\(unopened.count) without a session"
                 + (unopened.isEmpty ? "" : " — \(unopened.map(\.username).joined(separator: ", "))"))
            // ACCEPTED friendships only. `sync()` returns pending invites in the
            // same array, and the conversation + presence grants are written on
            // ACCEPT (`/friends/accept` → grantFriendTopic), not on invite. So
            // subscribing for an unaccepted inviter asks the broker for a topic
            // this account has no `mqtt_acl` row for — and with
            // `deny_action = disconnect` the refusal does not merely fail, it
            // drops the link. The topic stayed in `desiredTopics`, so every
            // reconnect asked again: connect, subscribe, denied, dropped,
            // forever.
            //
            // That is the whole "someone adds you and your app starts looping"
            // report. The invitee never even reached the screen where they could
            // accept, which was the one action that would have created the grant.
            let subscribable = friends.filter { $0.inviteStatus == .accepted }
            await mqtt.subscribeFriends(subscribable.map { $0.peerID })
            // No handshake sweep here any more. A session opens when there is a
            // message to send, from the peer's PUBLISHED prekeys — so a contact
            // with nothing to say costs no frames, no biometric prompt on the
            // far device, and no "setting up" state to get stuck in.
            //
            // What does need doing on every sync is keeping OUR bundle stocked,
            // since that is what lets others open a session with us while this
            // device is offline.
            await prekeys?.ensurePublished()
            ProtocolLog.record(.directorySynced(
                friends: friends.count,
                withoutSession: unopened.count,
                withoutKey: friends.filter { !$0.hasPinnedKey }.count))
            return friends
        } catch {
            dlog("[ChatSession] directory sync failed: \(error)")
            return []
        }
    }

    // MARK: - Keeping the graph fresh

    private var directoryPoll: Task<Void, Never>?

    /// How often to re-ask for the friend graph.
    ///
    /// One interval now. The fast variant existed because a handshake could be
    /// outstanding and needed retrying — an offer published into a topic with no
    /// subscriber was simply lost, so the poll was the retry. Sessions open from
    /// published prekeys instead, and the `init` frame goes to the peer's inbox
    /// where the broker queues it, so there is nothing left to retry.
    private static let pollInterval: UInt64 = 60_000_000_000

    /// Re-ask for the friend graph on a timer, because nothing tells us when it
    /// changes.
    ///
    /// Accepting an invite grants BOTH members their topics server-side, but only
    /// the accepting side learns of it — it syncs straight after the POST. The
    /// inviter finds out on its next sync, and until #92 there was no next sync:
    /// `refreshDirectory` runs on connect, on reconnect, on link-up, and on the
    /// iOS foreground. A Mac that stays connected never ran one at all.
    ///
    /// It also fixes the documented V0 wart where an invite arriving while the
    /// app is open only appears after a relaunch.
    ///
    /// The handshake half of that story is gone: an offer used to be published
    /// into a topic with no subscriber on it, which MQTT drops, so neither side
    /// ever spoke again and both contacts sat at "setting up". The `init` frame
    /// goes to the peer's inbox now, which they are subscribed to and which the
    /// broker queues while they are offline. What remains is only the graph
    /// itself, which still nothing pushes.
    private func startDirectoryPoll() {
        directoryPoll?.cancel()
        // Inherits the MainActor from this method, so the state it reads is the
        // same state the rest of the class mutates.
        directoryPoll = Task { [weak self] in
            while !Task.isCancelled {
                let interval = Self.pollInterval
                // Not `try?`: a cancelled sleep throws immediately, and
                // swallowing that would spin this loop at full speed — the same
                // bug #84 fixed in the unlock backoff.
                do { try await Task.sleep(nanoseconds: interval) } catch { return }
                guard let self, self.state == .connected else { return }
                await self.refreshDirectory()
            }
        }
    }

    private func stopDirectoryPoll() {
        directoryPoll?.cancel()
        directoryPoll = nil
    }

    /// Open a session with `friend` by claiming their published prekeys, and
    /// return the first sealed frame ready to publish.
    ///
    /// This replaces the v1 offer/answer exchange entirely. That needed both
    /// devices online at once, cost the peer a biometric prompt to answer, and
    /// could stall half-finished with no way for either side to tell which half
    /// was missing — hence the offer backoff, the fast directory poll, and the
    /// "setting up" state a contact could sit in forever. None of that exists
    /// here: the bundle comes from the server, the session is derived locally,
    /// and the first message rides in the same frame.
    ///
    /// Returns nil when the peer has published nothing (a contact who has not
    /// opened the app since prekeys shipped) or the claim fails. The caller
    /// surfaces that as a send failure, because that is what it is.
    @discardableResult
    func startSession(with friend: Friend) async -> Bool {
        guard !friend.hasSession else { return true }
        // Nothing can be sealed for an identity that no longer exists: there is
        // no key to encapsulate to and no topic anyone holds a grant on.
        guard !friend.isVanished else { return false }
        // The identity key has to be in hand BEFORE the claim, because claiming
        // CONSUMES one of the peer's one-time prekeys — spending one on a
        // contact whose key we cannot establish would burn it for nothing.
        guard friend.hasPinnedKey else {
            dlog("[ChatSession] ❌ no verified identity key for \(friend.username) yet")
            ProtocolLog.record(.dropped(stage: "start-session", peerID: friend.peerID,
                                        reason: "no verified identity key pinned yet"))
            lastSessionFailure[friend.peerID] =
                "hasn't published a key we can verify yet — try again in a moment"
            return false
        }
        do {
            let claimed = try await api.claimPrekey(peer: friend.peerID)
            guard let mediumPk = Data(hexString: claimed.medium) else {
                dlog("[ChatSession] ❌ \(friend.username)'s medium-term prekey is not hex")
                return false
            }
            let oneTimePk = claimed.oneTime.flatMap { Data(hexString: $0.prekey) }
            if oneTimePk == nil {
                dlog("[ChatSession] ⚠️ \(friend.username) had no one-time prekey — "
                     + "this session's forward secrecy runs to their next rotation")
            }

            // The IDENTITY key is the PINNED one, never anything the claim
            // returned. That is what makes a substituted prekey worthless to the
            // server: it cannot produce the identity shared secret, so it cannot
            // derive the root however it answers this call.
            //
            // "Pinned" means something stronger than "whatever we saw first"
            // now: `Friend.pin(publicKeyHex:)` only stores a key that hashes to
            // the contact's id, so the server cannot have substituted this one
            // either.
            let bundle = PrekeyBundle(
                identityPk: friend.publicKey,
                mediumPk: mediumPk,
                oneTimePk: oneTimePk,
                oneTimeId: oneTimePk == nil ? nil : claimed.oneTime?.id
            )
            let started = try RatchetSession.startAsInitiator(kem: kem, bundle: bundle)
            friend.ratchetSession = started.state
            dlog("[ChatSession] ✅ session opened with \(friend.username)")
            ProtocolLog.record(.sessionOpenedAsInitiator(peer: friend.peerID,
                                                         usedOneTime: oneTimePk != nil))
            return true
        } catch {
            dlog("[ChatSession] ❌ could not open a session with \(friend.username): \(error)")
            // Remembered so the composer can say WHICH failure this was. A peer
            // who has published no prekeys is a real, explainable state — they
            // have not opened the app recently — and it is not the same as the
            // network being down.
            lastSessionFailure[friend.peerID] = Self.describe(error)
            return false
        }
    }

    /// Why the last attempt to open a session with a peer failed, if it did.
    private var lastSessionFailure: [String: String] = [:]

    /// Turn a claim failure into something worth showing a person.
    private static func describe(_ error: Error) -> String {
        if case APIClient.APIError.badResponse(let code, _) = error {
            switch code {
            case 404: return "hasn't set up encryption keys yet — they need to open the app once"
            case 403: return "isn't in your contacts on the server any more"
            // The caps that replaced the paywall. 402 used to mean "requires a
            // subscription to message"; nothing produces it now.
            case 409: return "can't be added — one of you has reached the contact limit"
            case 429: return "couldn't be reached — too many requests, try again shortly"
            default:  return "couldn't be reached (server said \(code))"
            }
        }
        return "couldn't be reached"
    }

    /// Seal `text` for `friend`, returning the frame to publish.
    ///
    /// Opens a session first if there is none — which is what makes the FIRST
    /// message ratcheted, and sendable while the peer is offline. v1 could not do
    /// this: it needed a live round trip before any message could be sealed at all.
    func sealMessage(_ text: String, to friend: Friend, msgId: String) async throws -> ConversationFrame {
        if !friend.hasSession {
            await startSession(with: friend)
            guard friend.hasSession else {
                // Names the actual reason where there is one — "couldn't start a
                // secure session" told the user nothing they could act on.
                let why = lastSessionFailure[friend.peerID] ?? "couldn't be reached"
                throw AppError.crypto("\(friend.username) \(why).")
            }
        }
        guard var session = friend.ratchetSession else {
            throw AppError.crypto("Couldn't start a secure session with this contact yet.")
        }

        let sealed = try RatchetSession.seal(kem: kem, state: &session)
        // Present until the peer answers, so a failed or retried send still
        // carries the handshake (see RatchetSessionState.pendingInit).
        let initHeader = sealed.initHeader

        // Build the header BEFORE encrypting: the header IS the AAD, so the
        // payload has to be sealed against a finished one. `encoded()` re-derives
        // the same bytes, so the two cannot drift apart.
        //
        // There is one wire format. `Deployment.wireVersion` chose between two
        // and went with v2.
        let isInit = initHeader != nil
        let fields = ConversationFrame(
            t: isInit ? .initiate : .message,
            sender: myID,
            // Bound as AAD, which is what makes the topic check a belt rather
            // than the only thing holding the braces up. v2 had no recipient
            // field at all.
            to: friend.peerID,
            msgId: msgId,
            cid: sealed.header.cid,
            n: sealed.header.n,
            pn: sealed.header.pn,
            rk: initHeader?.rk ?? sealed.header.rk,
            // An init has no peer ratchet key to encapsulate against, so it
            // carries no `kemCt`. v2 tolerated one; the format refuses it.
            kemCt: isInit ? nil : sealed.header.kemCt,
            ctId: initHeader?.ctId,
            ctMt: initHeader?.ctMt,
            ctOt: initHeader?.ctOt,
            otId: initHeader?.otId,
            // On `init` only. It is the frame a peer may receive before they
            // have ever fetched our key, and they verify it against `sender`
            // rather than trusting it. Repeating 14 kB on every message
            // afterwards would undo most of what the id buys.
            senderPk: isInit ? Self.unhexPublicKey(myPublicKeyHex) : nil
        )
        // Nil when these fields cannot make a well-formed frame. Reachably: a
        // contact whose `peerID` an invite created and a directory sync has not
        // filled in yet, or no profile loaded at all — neither of which was
        // checked before. On v2 that produced a frame the receiver rejected; on
        // v3 a perfectly well-formed one naming client 0000…0000.
        //
        // Caught HERE rather than at publish, because by then a message has been
        // sealed against a header nobody can place, and the user's send has been
        // silently consumed.
        guard let aad = fields.header() else {
            throw AppError.crypto("\(friend.username) isn't ready to receive messages yet.")
        }
        let payload = try AESService.encryptRaw(plaintext: text,
                                                key: SymmetricKey(data: sealed.key),
                                                aad: aad)
        friend.ratchetSession = session
        return fields.withPayload(payload)
    }

    // MARK: - Messaging

    /// Our own client id — the `sender` on every frame we publish.
    var myID: String { profileManager?.currentProfile?.peerID ?? "" }

    /// Our own public key, hex. Needed on `init` frames alone (as `senderPk`),
    /// so a peer who has never fetched it can answer without a round trip.
    private var myPublicKeyHex: String { profileManager?.currentProfile?.publicKeyHex ?? "" }

    /// The profile stores the key as hex; the frame wants bytes, and v2's
    /// spelling converts it back. `PeerID.matches` hashes the hex TEXT, so hex
    /// stays the storage form on both sides of this.
    private static func unhexPublicKey(_ text: String) -> Data? {
        guard text.count % 2 == 0, !text.isEmpty else { return nil }
        var out = Data(capacity: text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }

    /// Publish a frame to `friend`, on whichever topic can actually deliver it.
    ///
    /// An `init` goes to the peer's INBOX, everything else to the shared
    /// conversation topic. The distinction is delivery, not secrecy: MQTT drops a
    /// publish to a topic nobody has subscribed to, which is exactly what a
    /// brand-new friendship is — the outage the directory poll used to paper
    /// over. Every client subscribes to its own inbox on connect with
    /// `cleanSession = false`, so the broker queues it for an offline peer.
    func publish(_ envelope: ConversationFrame, to friend: Friend) {
        let id = friend.peerID
        guard !id.isEmpty else { return }
        guard let data = envelope.encoded() else {
            // Encoding a struct of Strings and Ints cannot fail in practice, but
            // publishing an empty frame would look like a delivered message that
            // silently decrypts to nothing at the far end.
            dlog("[ChatSession] ❌ could not encode a \(envelope.t == .initiate ? "init" : "msg") frame for \(friend.username)")
            return
        }
        let isInit = envelope.t == .initiate
        Task {
            if isInit {
                await mqtt.sendToInbox(data, peerID: id)
                ProtocolLog.record(.initPublished(to: id))
            } else {
                await mqtt.send(data, toFriendID: id)
            }
        }
    }

    /// Publish a challenge or a proof on the handshake topic.
    ///
    /// A separate topic from the conversation, and separate from the inbox: every
    /// friend may publish to an inbox, so a challenge sitting there would be
    /// readable — and forgeable — by exactly the attacker the exchange exists to
    /// stop. Only the two members are granted this one.
    func publishHandshake(_ bytes: Data, to friend: Friend) {
        let id = friend.peerID
        guard !id.isEmpty, !myID.isEmpty else { return }
        Task { await mqtt.publishHandshake(bytes, toFriendID: id) }
    }

    /// Seal, persist and publish one message, without a view in the loop.
    ///
    /// ChatView keeps its own send path because it owns what a person needs
    /// around one: a bubble that appears immediately, a retry, an error to read.
    /// This is the mechanism for a message the APP sends — where there is no
    /// composer to report into and the only sensible response to failure is to
    /// leave the conversation as it was.
    ///
    /// Returns whether the frame went out. A false is ordinary: the peer may
    /// have published no prekeys yet, in which case there is nothing to open a
    /// session with and nothing to send.
    @discardableResult
    func sendText(_ text: String, to friend: Friend) async -> Bool {
        guard let modelContext else { return false }
        let messageId = UUID().uuidString
        do {
            let envelope = try await sealMessage(text, to: friend, msgId: messageId)
            let message = Message(content: text, isOutgoing: true, friend: friend,
                                  messageId: messageId, deliveryStatus: .sending)
            modelContext.insert(message)
            publish(envelope, to: friend)
            message.advanceDelivery(to: .sent)
            try? modelContext.save()
            return true
        } catch {
            // Deliberately nothing persisted. A half-sent greeting that shows in
            // the transcript but never left the device is worse than no greeting:
            // the user believes they said hello.
            dlog("[ChatSession] could not send on the user's behalf: \(error)")
            return false
        }
    }

    /// Re-send every outgoing message on a contact, over whatever session is
    /// current.
    ///
    /// Called after yielding a simultaneous start. The peer ignored our `init`
    /// exactly as we nearly ignored theirs, so nothing we sent on this contact
    /// ever reached them — which is why re-sending ALL of it is right rather
    /// than excessive. In practice that is the greeting and anything typed in
    /// the seconds before the race resolved, because a contact we had never
    /// heard from is a contact with no history.
    ///
    /// Message ids are preserved, so a peer that somehow did see one of these
    /// discards the duplicate instead of showing it twice.
    func resendUnconfirmed(to friend: Friend) async {
        let outgoing = (friend.messages ?? [])
            .filter { $0.isOutgoing }
            .sorted { $0.timestamp < $1.timestamp }
        guard !outgoing.isEmpty else { return }

        var sent = 0
        for message in outgoing {
            guard let id = message.messageId else { continue }
            do {
                let envelope = try await sealMessage(message.content, to: friend, msgId: id)
                publish(envelope, to: friend)
                sent += 1
            } catch {
                // Stop at the first failure rather than pressing on: the ratchet
                // advances per message, so sending the rest out of order would
                // leave gaps the peer cannot bridge.
                dlog("[ChatSession] resend to \(friend.username) stopped: \(error)")
                break
            }
        }
        ProtocolLog.record(.resent(peer: friend.peerID, count: sent))
        try? modelContext?.save()
    }

    /// Stop following an unfriended peer's topics.
    func unsubscribe(friend: Friend) async {
        await mqtt.unsubscribeFriend(friend.peerID)
    }

    /// Presence, published explicitly rather than left to the Last-Will: on iOS
    /// the socket is frozen (not closed) when we go behind, so without this the
    /// broker keeps us "online" until keepalive lapses — and the push-bridge,
    /// which decides whether to wake the device from exactly that flag, stays
    /// quiet for the whole window.
    ///
    /// Returns whether the frame actually reached the socket, so the caller that
    /// is racing an iOS suspension can hold its background assertion until it
    /// has. `false` means either there was no live session or the frame is
    /// buffered for a reconnect — in both cases the broker still has us marked
    /// online, and the Last-Will is the only thing that will correct it.
    @discardableResult
    func setPresence(online: Bool) async -> Bool {
        let written = await mqtt.publishPresence(online: online)
        ProtocolLog.record(.presenceAnnounced(online: online, written: written))
        return written
    }

    // MARK: - Link events

    private func linkChanged(connected: Bool, error: Error?) {
        if connected {
            state = .connected
            Task { await refreshDirectory() }
            startDirectoryPoll()
            onConnected?()
        } else {
            let wasUp = state == .connected
            state = .idle
            stopDirectoryPoll()
            router?.clearAllPresence()
            if wasUp || error != nil { onDisconnect?() }
        }
    }

    /// The scope of the live session — which door minted it.
    func currentScope() async -> AuthService.Scope {
        await auth.scope()
    }
}
