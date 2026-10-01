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
    /// Always an authorization decision here: the static ACL (acl.conf) does not
    /// allow that topic to this client id — a wildcard, someone else's inbox, or
    /// a retired `c/`/`h/` topic from an older build.
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
    /// Drop a link presumed dead and report it as `.disconnected`, so the
    /// reconnect loop runs. No DISCONNECT goes out; the broker fires our Will.
    func abandonLink()
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
    /// Chooses the transport order per connect; shared so what one connect
    /// learned about this network (a blocked gateway port) holds for the next.
    private let selector: TransportSelector
    /// Whether a failure before CONNACK is reported to the connection handler —
    /// false for every attempt but the last.
    private var reportAttemptFailure = true
    /// The transport the live session is on, for diagnostics.
    private(set) var activeTransport: TransportSelector.Kind?

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

    init(backend: MQTTBackend, auth: AuthService, selector: TransportSelector = .shared) {
        self.backend = backend
        self.auth = auth
        self.selector = selector
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
        // carries over to it. The wanted topics include the previous profile's
        // own inbox and graph, which this identity may not subscribe to, and its
        // conversations, which this identity has no business reading. Presence
        // goes with it — an online set belonging to the account we just left is
        // not ours to report.
        if let previous = myID, previous != id {
            desired.removeAll()
            followed.removeAll()
            onlineFriends.removeAll()
        }
        myID = id

        // Which transports, in which order (TransportSelector): hqn/1 over raw
        // TCP when this server has a gateway and this network has not been
        // seen to block it, then WSS — always WSS last.
        if ServerConfig.hqnDiscoveryIsStale() { await auth.refreshTransportDiscovery() }
        let network = Reachability.currentNetworkKey
        let attempts = selector.plan(hqn: ServerConfig.hqnEndpoint, wss: ServerConfig.mqttURL, network: network)

        for (i, attempt) in attempts.enumerated() {
            let isLast = i == attempts.count - 1
            let started = Date()
            do {
                try await attemptConnect(id: id, url: attempt.url, deadline: attempt.deadline, isLast: isLast)
                selector.record(attempt.kind, succeeded: true,
                                seconds: Date().timeIntervalSince(started), network: network)
                activeTransport = attempt.kind
                if i > 0 { schedulePresenceRepair(for: id) }
                return
            } catch {
                // Refused credentials are not a transport problem: every
                // transport would be refused the same way, and the next connect
                // refreshes the key (see handle(.disconnected)).
                if case MQTTWireClient.MQTTError.connectionRefused = error { throw error }
                selector.record(attempt.kind, succeeded: false, seconds: nil, network: network)
                if isLast { throw error }
            }
        }
    }

    /// One transport attempt: sign a FRESH CONNECT (its nonce is single-use, so
    /// a CONNECT that reached the broker over one transport cannot be reused on
    /// the next), connect, and wait for CONNACK — or for the deadline, after
    /// which the half-open link is abandoned so the next transport can start.
    private func attemptConnect(id: String, url: URL, deadline: TimeInterval?, isLast: Bool) async throws {
        let password = try await auth.mqttConnectPassword(clientID: id)
        // An attempt that fails before CONNACK is not a "disconnect" the app
        // should act on — unless it is the last one. Reported, a failed hqn/1
        // attempt would start the app's reconnect loop underneath the fallback.
        reportAttemptFailure = isLast
        backend.connect(
            url: url,
            clientID: id,
            username: id,
            password: password,
            willTopic: MQTTTopics.presence(id),
            willPayload: presencePayload(online: false)
        ) { [weak self] event in
            guard let self else { return }
            Task { await self.handle(event) }
        }

        let timer: Task<Void, Never>? = deadline.map { seconds in
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                guard !Task.isCancelled else { return }
                await self?.abandonIfStillConnecting()
            }
        }
        defer { timer?.cancel() }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connectWaiters.append(cont)
        }
    }

    private func abandonIfStillConnecting() {
        guard !isConnected, !connectWaiters.isEmpty else { return }
        backend.abandonLink()
    }

    /// After a fallback, the abandoned attempt may still have reached the
    /// broker — and its Last-Will ("offline", retained) can land AFTER the
    /// "online" this session published. Saying "online" once more, shortly
    /// after, makes the last word the true one.
    private func schedulePresenceRepair(for id: String) {
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            await self?.republishPresenceIfConnected(id)
        }
    }

    private func republishPresenceIfConnected(_ id: String) {
        guard isConnected, myID == id else { return }
        backend.publish(MQTTTopics.presence(id), payload: presencePayload(online: true),
                        qos: 1, retained: true, onWrite: nil)
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

    /// The device's network path changed under a live link. A socket bound to
    /// the old path can look healthy for minutes, so drop it now; the
    /// `.disconnected` it produces drives the normal reconnect.
    func abandonLink() {
        guard isConnected else { return }
        backend.abandonLink()
    }

    // MARK: Subscriptions

    /// The topics each followed friend was subscribed on. Kept so an unfriend
    /// can leave them, and so a re-friend — which mints NEW topic ids — leaves
    /// the old ones rather than holding both.
    private var followed: [String: FriendTopics] = [:]

    /// Follow a friend's conversation + presence, on the topics the directory
    /// handed out. Recorded so a reconnect restores it.
    func subscribeFriend(_ friendID: String, topics: FriendTopics) {
        guard myID != nil, !friendID.isEmpty else { return }
        if let old = followed[friendID], old != topics {
            // Re-friended between two syncs: the old ids are retired.
            for t in [old.conversation, old.handshake] {
                desired.forget(t)
                backend.unsubscribe(t)
            }
        }
        followed[friendID] = topics
        desired.want(topics.conversation, qos: 1)
        desired.want(MQTTTopics.presence(friendID), qos: 0)
        // The handshake topic rides with the conversation: they are handed out
        // together and there is no reason to hold one without the other.
        desired.want(topics.handshake, qos: 1)
        guard isConnected else { return }
        backend.subscribe(topics.conversation, qos: 1)
        backend.subscribe(MQTTTopics.presence(friendID), qos: 0)
        backend.subscribe(topics.handshake, qos: 1)
        ProtocolLog.record(.subscribed(topic: .conversation, peer: friendID))
        ProtocolLog.record(.subscribed(topic: .presence, peer: friendID))
    }

    func subscribeFriends(_ friends: [(id: String, topics: FriendTopics)]) {
        friends.forEach { subscribeFriend($0.id, topics: $0.topics) }
    }

    /// Stop following a friend (after unfriend).
    func unsubscribeFriend(_ friendID: String) {
        let presence = MQTTTopics.presence(friendID)
        var topics = [presence]
        if let t = followed.removeValue(forKey: friendID) {
            topics += [t.conversation, t.handshake]
        }
        for t in topics {
            desired.forget(t)
            backend.unsubscribe(t)
        }
        onlineFriends.remove(friendID)
    }

    // MARK: Publish

    /// Publish an end-to-end-encrypted payload to a friend's conversation topic.
    func send(_ payload: Data, on topics: FriendTopics) {
        guard myID != nil else { return }
        backend.publish(topics.conversation, payload: payload,
                        qos: 1, retained: false, onWrite: nil)
    }

    /// Publish to a peer's INBOX rather than the shared conversation topic.
    ///
    /// This is where an `init` frame goes, and the reason is delivery, not
    /// secrecy: MQTT drops a publish to a topic with no subscriber, and a brand
    /// new friendship is exactly that — the peer has never subscribed to the
    /// conversation topic. Every client subscribes to its own inbox on connect
    /// with `cleanSession = false`, so the broker QUEUES for an offline peer
    /// instead of discarding. The broker lets anyone publish to an inbox
    /// (acl.conf); the recipient's router is what refuses a stranger's `init`.
    func sendToInbox(_ payload: Data, peerID: String) {
        backend.publish(MQTTTopics.inbox(peerID), payload: payload,
                        qos: 1, retained: false, onWrite: nil)
    }

    /// Publish a challenge or a proof on the handshake topic.
    ///
    /// QoS 1, like everything that matters: a challenge issued while the peer is
    /// offline is queued rather than dropped, and the exchange completes the
    /// moment they come back.
    func publishHandshake(_ payload: Data, on topics: FriendTopics) {
        guard myID != nil else { return }
        backend.publish(topics.handshake, payload: payload,
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
            // From here on a drop is a real disconnect, whichever attempt this was.
            reportAttemptFailure = true
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
            // Refused credentials: the key we signed with is not one the broker
            // accepts any more, so the next connect must refresh, not re-sign.
            if case MQTTWireClient.MQTTError.connectionRefused(let code)? = error, code == 4 || code == 5 {
                Task { await auth.invalidateMqttKey() }
            }
            let wasConnected = isConnected
            isConnected = false
            onlineFriends.removeAll()
            ProtocolLog.record(.disconnected(reason: error.map { "\($0)" } ?? "closed"))
            resumeWaiters(with: error ?? CancellationError())
            // A transport attempt that fails before CONNACK, with another one
            // still to come, is the fallback's business — not the app's.
            if wasConnected || reportAttemptFailure { connectionHandler?(false, error) }

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
            // STOP ASKING. Under the old `deny_action = disconnect` a refusal
            // also dropped the link, so a topic left in `desiredTopics` looped
            // every reconnect. The broker only refuses the packet now, but a
            // refused topic is still not worth re-offering on every connect.
            //
            // Forgetting it is safe: `subscribeFriend` runs on every directory
            // sync, with whatever topics the server currently hands out.
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
