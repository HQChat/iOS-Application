import Foundation

/// MQTT client for messaging + presence (see deploy/EXTRACTION_PLAN.md). It owns
/// the app-level concerns — topic scheme, presence publish/track, subscription
/// bookkeeping, routing — and delegates the wire protocol to an injected
/// `MQTTBackend`, implemented by `MQTTWireClient`.
///
/// Transport is MQTT-over-WSS to `ServerConfig.mqttURL` (nginx → EMQX), pinned
/// with the same `TLSPinningDelegate` the REST calls use (IOS-1). End-to-end
/// content encryption (RatchetSession/AESService) is unchanged — ciphertext rides
/// inside the MQTT payload exactly as it did inside the WS frame.

// MARK: - Backend seam (implement with CocoaMQTT / MQTTNIO)

enum MQTTEvent {
    case connected
    case disconnected(Error?)
    case message(topic: String, payload: Data)
    /// The broker answered a SUBSCRIBE with a failure return code (>= 0x80).
    /// Always an authorization decision here: the topic has no `mqtt_acl` row
    /// for this client id.
    case subscribeRefused(topic: String, code: UInt8)
    /// A QoS-1 publish is being re-sent after a reconnect.
    case publishReplayed(topic: String, attempt: Int)
    /// A QoS-1 publish was abandoned after too many unacknowledged replays.
    /// Under `deny_action = disconnect` this is what a refused PUBLISH looks
    /// like from here — there is no negative acknowledgement to read, only a
    /// packet that is never acked and a link that dies each time it is sent.
    case publishAbandoned(topic: String, attempts: Int)
}

/// Minimal surface the concrete MQTT library adapter must provide.
protocol MQTTBackend: AnyObject {
    /// Connect with a Last-Will (retained) so an ungraceful drop flips presence
    /// to offline. `clientID` MUST equal our client id — EMQX keys the topic ACL
    /// on it (`WHERE id = ${clientid}`).
    func connect(url: URL, clientID: String, username: String, password: String,
                 willTopic: String, willPayload: Data,
                 onEvent: @escaping (MQTTEvent) -> Void)
    func subscribe(_ topic: String, qos: Int)
    func unsubscribe(_ topic: String)
    /// `onWrite` fires when the frame reached the socket (`true`) or was
    /// buffered for a session that is not up (`false`). Only the presence flip
    /// waits on it — see `MQTTService.publishPresence`.
    func publish(_ topic: String, payload: Data, qos: Int, retained: Bool,
                 onWrite: ((Bool) -> Void)?)
    func disconnect()
}

// Topics and inbound routing live in MQTTTopics.swift — the routing decision
// is a pure function so it can be tested without a socket, and so a topic kind
// that nothing routes is a compile error rather than a silent drop.

// MARK: - Service

actor MQTTService {

    private let backend: MQTTBackend
    private let auth: AuthService
    /// Our own client id — what we connect as and what our topics are named for.
    private var myID: String?
    private var isConnected = false

    /// Friends currently seen online, by client id (from their retained/LWT
    /// presence).
    private var onlineFriends = Set<String>()

    /// Topics we intend to hold, so a reconnect restores them. EMQX keeps
    /// subscriptions for a persistent session, but re-sending them is cheap and
    /// removes any dependence on broker-side state surviving.
    private var desired = SubscriptionLedger()

    /// Suspended `connect(id:)` callers, resumed on CONNACK or on failure.
    private var connectWaiters: [CheckedContinuation<Void, Error>] = []

    /// Delivered for each conversation message: (topic, ciphertext).
    private var messageHandler: ((_ topic: String, _ payload: Data) -> Void)?
    /// Delivered for each challenge/proof frame: (topic, bytes).
    private var handshakeHandler: ((_ topic: String, _ payload: Data) -> Void)?
    /// Called when the server says the friend graph moved.
    private var graphHandler: (() -> Void)?
    /// Delivered when a friend's presence flips: (friendID, isOnline).
    private var presenceHandler: ((_ friendID: String, _ online: Bool) -> Void)?
    /// Delivered when the link comes up or goes down.
    private var connectionHandler: ((_ connected: Bool, _ error: Error?) -> Void)?

    init(backend: MQTTBackend, auth: AuthService) {
        self.backend = backend
        self.auth = auth
    }

    func setMessageHandler(_ h: @escaping (_ topic: String, _ payload: Data) -> Void) { messageHandler = h }
    func setHandshakeHandler(_ h: @escaping (_ topic: String, _ payload: Data) -> Void) { handshakeHandler = h }
    func setGraphHandler(_ h: @escaping () -> Void) { graphHandler = h }
    func setPresenceHandler(_ h: @escaping (_ friendID: String, _ online: Bool) -> Void) { presenceHandler = h }
    func setConnectionHandler(_ h: @escaping (_ connected: Bool, _ error: Error?) -> Void) { connectionHandler = h }
    func isFriendOnline(_ friendID: String) -> Bool { onlineFriends.contains(friendID) }

    // MARK: Connect

    /// Rotate a fresh MQTT token, connect, and suspend until the broker either
    /// accepts the session (CONNACK) or refuses it. Publishes our presence online
    /// (retained) and restores subscriptions on success.
    func connect(id: String) async throws {
        // A different id is a different account, and none of the state below
        // carries over to it. `desiredTopics` is keyed by OUR id —
        // `c/{hash(me, friend)}` — so restoring it after a profile switch
        // re-subscribes to the previous profile's conversations, which this
        // identity holds no grant on. EMQX runs `deny_action = disconnect`, so
        // that is not a refused SUBACK: the broker drops the connection the
        // moment CONNACK has landed, the reconnect asks for the same topics, and
        // the app sits in a loop that only quitting it clears. Presence goes with
        // it — an online set belonging to the account we just left is not ours to
        // report.
        if let previous = myID, previous != id {
            desired.removeAll()
            onlineFriends.removeAll()
        }
        myID = id
        let token = try await auth.refreshMqttToken()   // rotated on every connect
        let willTopic = MQTTTopics.presence(id)
        let willPayload = presencePayload(online: false)

        backend.connect(
            url: ServerConfig.mqttURL,
            clientID: id,
            username: id,
            password: token,
            willTopic: willTopic,
            willPayload: willPayload
        ) { [weak self] event in
            guard let self else { return }
            Task { await self.handle(event) }
        }

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connectWaiters.append(cont)
        }
    }

    func disconnect() {
        // Best-effort graceful offline before tearing down, so the peer's roster
        // updates immediately instead of waiting for the Last-Will.
        if let id = myID, isConnected {
            backend.publish(MQTTTopics.presence(id), payload: presencePayload(online: false),
                            qos: 1, retained: true, onWrite: nil)
        }
        backend.disconnect()
        isConnected = false
        onlineFriends.removeAll()
        resumeWaiters(with: CancellationError())
    }

    // MARK: Subscriptions

    /// Follow a friend's conversation + presence. Recorded so a reconnect
    /// restores it.
    func subscribeFriend(_ friendID: String) {
        guard let me = myID, !friendID.isEmpty else { return }
        desired.want(MQTTTopics.conversation(me, friendID), qos: 1)
        desired.want(MQTTTopics.presence(friendID), qos: 0)
        // The handshake topic rides with the conversation: they are granted
        // together and there is no reason to hold one without the other.
        desired.want(MQTTTopics.handshake(me, friendID), qos: 1)
        guard isConnected else { return }
        backend.subscribe(MQTTTopics.conversation(me, friendID), qos: 1)
        backend.subscribe(MQTTTopics.presence(friendID), qos: 0)
        backend.subscribe(MQTTTopics.handshake(me, friendID), qos: 1)
        ProtocolLog.record(.subscribed(topic: .conversation, peer: friendID))
        ProtocolLog.record(.subscribed(topic: .presence, peer: friendID))
    }

    func subscribeFriends(_ friendIDs: [String]) { friendIDs.forEach { subscribeFriend($0) } }

    /// Stop following a friend (after unfriend).
    func unsubscribeFriend(_ friendID: String) {
        guard let me = myID else { return }
        let convo = MQTTTopics.conversation(me, friendID)
        let presence = MQTTTopics.presence(friendID)
        let handshake = MQTTTopics.handshake(me, friendID)
        desired.forget(convo)
        desired.forget(presence)
        desired.forget(handshake)
        backend.unsubscribe(handshake)
        backend.unsubscribe(convo)
        backend.unsubscribe(presence)
        onlineFriends.remove(friendID)
    }

    // MARK: Publish

    /// Publish an end-to-end-encrypted payload to a friend's conversation topic.
    func send(_ payload: Data, toFriendID friendID: String) {
        guard let me = myID else { return }
        backend.publish(MQTTTopics.conversation(me, friendID), payload: payload,
                        qos: 1, retained: false, onWrite: nil)
    }

    /// Publish to a peer's INBOX rather than the shared conversation topic.
    ///
    /// This is where an `init` frame goes, and the reason is delivery, not
    /// secrecy: MQTT drops a publish to a topic with no subscriber, and a brand
    /// new friendship is exactly that — the peer has never subscribed to the
    /// conversation topic. Every client subscribes to its own inbox on connect
    /// with `cleanSession = false`, so the broker QUEUES for an offline peer
    /// instead of discarding. The friendship grant carries `publish` on the
    /// peer's inbox (DB.grantFriendTopic); without it the broker refuses.
    func sendToInbox(_ payload: Data, peerID: String) {
        backend.publish(MQTTTopics.inbox(peerID), payload: payload,
                        qos: 1, retained: false, onWrite: nil)
    }

    /// Publish a challenge or a proof on the handshake topic.
    ///
    /// QoS 1, like everything that matters: a challenge issued while the peer is
    /// offline is queued rather than dropped, and the exchange completes the
    /// moment they come back.
    func publishHandshake(_ payload: Data, toFriendID friendID: String) {
        guard let me = myID else { return }
        backend.publish(MQTTTopics.handshake(me, friendID), payload: payload,
                        qos: 1, retained: false, onWrite: nil)
    }

    /// Announce our own presence. Retained, so a friend coming online later reads
    /// the current value rather than waiting for the next flip.
    ///
    /// It does not return until the frame has reached the socket, and answers
    /// whether it did. There is deliberately no fire-and-forget version: the
    /// push-bridge wakes a device only if presence says it is offline, and it
    /// decides that ONCE, when a message is published, with no retry. So the
    /// flip has to beat the message, not merely be requested before it.
    ///
    /// It used to return the instant the write was *scheduled*, which let iOS
    /// suspend the app on its way to the background with the frame still sitting
    /// in a dispatch queue. The broker — and the bridge — went on believing the
    /// device was reachable, and every message that arrived before keepalive
    /// lapsed produced no notification at all.
    @discardableResult
    func publishPresence(online: Bool) async -> Bool {
        guard let id = myID, isConnected else { return false }
        let topic = MQTTTopics.presence(id)
        let payload = presencePayload(online: online)
        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            // The backend calls this exactly once, on the socket's completion or
            // on the buffered path.
            backend.publish(topic, payload: payload, qos: 1, retained: true) { written in
                cont.resume(returning: written)
            }
        }
    }

    // MARK: Events

    private func handle(_ event: MQTTEvent) {
        switch event {
        case .connected:
            isConnected = true
            if let id = myID {
                backend.subscribe(MQTTTopics.inbox(id), qos: 1)
                backend.subscribe(MQTTTopics.graph(id), qos: 1)
                ProtocolLog.record(.connected(as: id))
                ProtocolLog.record(.subscribed(topic: .inbox, peer: nil))
                ProtocolLog.record(.subscribed(topic: .graph, peer: nil))
                for entry in desired.toSubscribe { backend.subscribe(entry.topic, qos: entry.qos) }
                backend.publish(MQTTTopics.presence(id), payload: presencePayload(online: true),
                                qos: 1, retained: true, onWrite: nil)
            }
            resumeWaiters(with: nil)
            connectionHandler?(true, nil)

        case .disconnected(let error):
            isConnected = false
            onlineFriends.removeAll()
            ProtocolLog.record(.disconnected(reason: error.map { "\($0)" } ?? "closed"))
            resumeWaiters(with: error ?? CancellationError())
            connectionHandler?(false, error)

        case .subscribeRefused(let topic, let code):
            // Named, not swallowed. With deny_action = disconnect the link is
            // about to die too, and this is the only line that says why.
            let kind: ProtocolLog.TopicKind
            switch MQTTTopics.route(topic) {
            case .presence:     kind = .presence
            case .inbox:        kind = .inbox
            case .handshake:    kind = .handshake
            case .graph:        kind = .graph
            // A refusal can only name a topic we asked for, and everything we
            // ask for that is not presence, an inbox or the graph topic is a
            // conversation.
            case .conversation, .unroutable: kind = .conversation
            }
            ProtocolLog.record(.subscribeRefused(topic: kind,
                                                 peer: MQTTTopics.peer(in: topic),
                                                 code: Int(code)))
            // STOP ASKING. `deny_action = disconnect` means a refusal also drops
            // the link, so a topic left in `desiredTopics` is re-offered on the
            // next connect and drops it again — a loop that survives every
            // reconnect and cannot resolve itself, because the only thing that
            // would grant the topic is an action the user cannot reach while the
            // app is thrashing.
            //
            // Forgetting it is safe: `subscribeFriend` runs on every directory
            // sync, so the moment the grant exists the topic is asked for again.
            desired.refused(topic)

        case .publishReplayed(let topic, let attempt):
            ProtocolLog.record(.publishReplayed(topic: MQTTTopics.describe(topic), attempt: attempt))

        case .publishAbandoned(let topic, let attempts):
            ProtocolLog.record(.publishAbandoned(topic: MQTTTopics.describe(topic), attempts: attempts))

        case .message(let topic, let payload):
            // Exhaustive on purpose. This was an if/else chain whose implicit
            // "otherwise" discarded every frame delivered to our own inbox —
            // where `init` frames go and nowhere else, so first contact could
            // never complete. A switch over a closed route type makes the next
            // topic kind a compile error instead of a silent loss.
            switch MQTTTopics.route(topic) {
            case .presence(let id):
                ProtocolLog.record(.received(route: .presence, bytes: payload.count))
                let online = presenceIsOnline(payload)
                if online { onlineFriends.insert(id) } else { onlineFriends.remove(id) }
                presenceHandler?(id, online)

            case .conversation:
                ProtocolLog.record(.received(route: .conversation, bytes: payload.count))
                messageHandler?(topic, payload)

            case .inbox:
                // The handshake. The topic goes WITH the payload: the router
                // checks that a frame of this kind, from this sender, was
                // entitled to arrive here — an `init` on our inbox, a `msg` only
                // on the conversation topic the two ids derive. This used to say
                // the handler "routes on the ENVELOPE, not on the topic", and
                // that was the hole: a `msg` naming a third party, published here
                // by any friend, was dispatched into that third party's session.
                ProtocolLog.record(.received(route: .inbox, bytes: payload.count))
                messageHandler?(topic, payload)

            case .handshake:
                // The exchange that authenticates an `init`. No envelope, no
                // ciphertext — see Handshake.swift.
                ProtocolLog.record(.received(route: .handshake, bytes: payload.count))
                handshakeHandler?(topic, payload)

            case .handshake:
                // The exchange that authenticates an `init`. Carries no
                // envelope and no ciphertext — see Handshake.swift.
                ProtocolLog.record(.received(route: .handshake, bytes: payload.count))
                handshakeHandler?(topic, payload)

            case .graph:
                // Carries nothing worth parsing: the fact of it IS the message.
                // Whatever the server put in the payload, the answer is to ask
                // `/friends` — which is authenticated, so a spoofed nudge buys
                // its sender one directory fetch on our behalf and no more.
                ProtocolLog.record(.received(route: .graph, bytes: payload.count))
                graphHandler?()

            case .unroutable(let reason):
                ProtocolLog.record(.received(route: .unroutable, bytes: payload.count))
                ProtocolLog.record(.dropped(stage: "mqtt-route", peerID: nil, reason: reason))
            }
        }
    }

    /// Resume everyone waiting on `connect(id:)` — success when `error` is nil.
    private func resumeWaiters(with error: Error?) {
        let waiters = connectWaiters
        connectWaiters.removeAll()
        for cont in waiters {
            if let error { cont.resume(throwing: error) } else { cont.resume() }
        }
    }

    // MARK: Presence payloads

    private func presencePayload(online: Bool) -> Data {
        (try? JSONSerialization.data(withJSONObject: ["s": online ? "online" : "offline"])) ?? Data()
    }
    private func presenceIsOnline(_ payload: Data) -> Bool {
        if let o = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
           let s = o["s"] as? String { return s == "online" }
        return false
    }
    // presenceID moved into MQTTTopics.route — one place decides what a topic
    // means, and it is unit-tested.
}
