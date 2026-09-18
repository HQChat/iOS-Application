import Foundation

/// MQTT 3.1.1 over WebSocket — the concrete `MQTTBackend` (Phase 4 of the MQTT
/// migration; see deploy/EXTRACTION_PLAN.md).
///
/// WHY HAND-ROLLED. The plan called for CocoaMQTT/MQTTNIO via SPM, but every
/// Swift MQTT library that speaks WSS brings its own WebSocket stack (Starscream
/// et al.) with its own TLS handling — and the one thing this client must not
/// lose is SPKI pinning (IOS-1). Running MQTT over `URLSessionWebSocketTask`
/// keeps the exact `TLSPinningDelegate` the REST calls use, adds no dependency,
/// and the subset of the protocol we need is small: the broker is EMQX, the QoS
/// ceiling is 1, and there are no retained-message or MQTT-5 property games
/// beyond a retained presence value.
///
/// What it implements: CONNECT/CONNACK (clean-session off, Last-Will, username +
/// password), PUBLISH/PUBACK in both directions at QoS 0/1, SUBSCRIBE/SUBACK,
/// UNSUBSCRIBE/UNSUBACK, PINGREQ/PINGRESP keepalive, DISCONNECT.
///
/// Session semantics worth knowing: `cleanSession = false` with `clientID = pk`
/// is what gives us the OFFLINE QUEUE — EMQX holds QoS-1 messages for a
/// disconnected client and replays them on reconnect, which is what replaced the
/// monolith's server-side queue. It is also why the push-bridge only has to send
/// a content-free wake.

// MARK: - Packet coding (pure; unit-testable without a socket)

enum MQTTPacketType: UInt8 {
    case connect = 1, connack = 2, publish = 3, puback = 4
    case subscribe = 8, suback = 9, unsubscribe = 10, unsuback = 11
    case pingreq = 12, pingresp = 13, disconnect = 14
}

/// One decoded packet: the fixed-header byte (type + flags) and the variable
/// header + payload that follow it.
struct MQTTPacket: Equatable {
    let header: UInt8
    let body: Data

    var type: MQTTPacketType? { MQTTPacketType(rawValue: header >> 4) }
    var flags: UInt8 { header & 0x0F }
}

enum MQTTCodec {

    // --- primitives ---------------------------------------------------------

    /// MQTT "remaining length": 7 bits per byte, high bit = continuation.
    static func encodeLength(_ length: Int) -> Data {
        var out = Data()
        var value = length
        repeat {
            var byte = UInt8(value % 128)
            value /= 128
            if value > 0 { byte |= 0x80 }
            out.append(byte)
        } while value > 0
        return out
    }

    /// The largest packet this client will accept before failing the connection.
    ///
    /// A four-byte remaining-length permits 268,435,455 bytes, and `ingest`
    /// buffers until the whole packet arrives — so without a ceiling a broker
    /// (or anything that reaches the socket) can make the client accumulate
    /// toward 256 MB while the ping timer keeps the link looking healthy.
    ///
    /// 256 kB is deliberately generous. The largest frame this protocol can
    /// produce is an `init` at roughly 82 kB, so this is 3x headroom, and it
    /// only gets roomier if the envelope ever moves to a binary framing. The
    /// asymmetry matters: too high merely delays a failure, while too low BRICKS
    /// the client from the client side, where no server-side change can rescue
    /// it — the same hazard `Deployment.pinnedSPKIHashes` documents for TLS pins.
    static let maxPacketBytes = 256 * 1024

    /// A size that no legitimate frame should reach, reported but not fatal.
    /// If this ever fires in a log, `maxPacketBytes` deserves a second look
    /// BEFORE a real packet trips it.
    static let packetWarningBytes = 128 * 1024

    /// What a remaining-length prefix turned out to be.
    ///
    /// Three states, because there are three situations and the old two-state
    /// `nil` conflated two of them: "more than four continuation bytes" (which
    /// its own comment called malformed and said the caller drops the stream)
    /// and "the buffer does not hold the length yet" (entirely normal). Both
    /// read as `nil`, both callers treated `nil` as "wait", and so a broker
    /// sending five continuation bytes left the client parsing nothing forever
    /// while `buffer` grew without bound and keepalive kept the link alive.
    enum LengthPrefix: Equatable {
        case complete(value: Int, bytes: Int)
        /// More bytes needed before the prefix can be read at all.
        case incomplete
        /// Not a length prefix, and never will be. Drop the connection.
        case malformed
    }

    static func decodeLength(_ data: Data, from offset: Int) -> LengthPrefix {
        var multiplier = 1
        var value = 0
        var index = offset
        var consumed = 0
        while index < data.count {
            let byte = data[data.startIndex + index]
            value += Int(byte & 0x7F) * multiplier
            consumed += 1
            if byte & 0x80 == 0 { return .complete(value: value, bytes: consumed) }
            // A fifth continuation byte cannot be part of a valid prefix: MQTT
            // 3.1.1 caps the encoding at four.
            if consumed == 4 { return .malformed }
            multiplier *= 128
            index += 1
        }
        return .incomplete
    }

    /// Length-prefixed UTF-8, the only string form MQTT 3.1.1 has.
    static func encodeString(_ s: String) -> Data {
        let bytes = Data(s.utf8)
        var out = Data([UInt8(bytes.count >> 8), UInt8(bytes.count & 0xFF)])
        out.append(bytes)
        return out
    }

    static func encodeData(_ d: Data) -> Data {
        var out = Data([UInt8(d.count >> 8), UInt8(d.count & 0xFF)])
        out.append(d)
        return out
    }

    static func packet(_ type: MQTTPacketType, flags: UInt8 = 0, body: Data) -> Data {
        var out = Data([(type.rawValue << 4) | flags])
        out.append(encodeLength(body.count))
        out.append(body)
        return out
    }

    // --- outbound packets ---------------------------------------------------

    static func connect(clientID: String, username: String, password: String,
                        willTopic: String?, willPayload: Data?, willRetain: Bool,
                        keepAlive: UInt16, cleanSession: Bool) -> Data {
        var body = encodeString("MQTT")
        body.append(0x04)                                   // protocol level 3.1.1

        var flags: UInt8 = 0
        if !username.isEmpty { flags |= 0x80 }
        if !password.isEmpty { flags |= 0x40 }
        if willTopic != nil {
            flags |= 0x04                                   // will flag
            flags |= (1 << 3)                               // will QoS 1
            if willRetain { flags |= 0x20 }
        }
        if cleanSession { flags |= 0x02 }
        body.append(flags)
        body.append(contentsOf: [UInt8(keepAlive >> 8), UInt8(keepAlive & 0xFF)])

        body.append(encodeString(clientID))
        if let willTopic, let willPayload {
            body.append(encodeString(willTopic))
            body.append(encodeData(willPayload))
        }
        if !username.isEmpty { body.append(encodeString(username)) }
        if !password.isEmpty { body.append(encodeString(password)) }
        return packet(.connect, body: body)
    }

    static func publish(topic: String, payload: Data, qos: Int, retained: Bool,
                        packetID: UInt16?, dup: Bool = false) -> Data {
        var flags: UInt8 = UInt8((qos & 0x03) << 1)
        if retained { flags |= 0x01 }
        if dup { flags |= 0x08 }
        var body = encodeString(topic)
        if qos > 0, let packetID {
            body.append(contentsOf: [UInt8(packetID >> 8), UInt8(packetID & 0xFF)])
        }
        body.append(payload)
        return packet(.publish, flags: flags, body: body)
    }

    static func puback(packetID: UInt16) -> Data {
        packet(.puback, body: Data([UInt8(packetID >> 8), UInt8(packetID & 0xFF)]))
    }

    static func subscribe(topic: String, qos: Int, packetID: UInt16) -> Data {
        var body = Data([UInt8(packetID >> 8), UInt8(packetID & 0xFF)])
        body.append(encodeString(topic))
        body.append(UInt8(qos & 0x03))
        return packet(.subscribe, flags: 0x02, body: body)   // reserved bits = 0010
    }

    static func unsubscribe(topic: String, packetID: UInt16) -> Data {
        var body = Data([UInt8(packetID >> 8), UInt8(packetID & 0xFF)])
        body.append(encodeString(topic))
        return packet(.unsubscribe, flags: 0x02, body: body)
    }

    static func pingreq() -> Data { packet(.pingreq, body: Data()) }
    static func disconnect() -> Data { packet(.disconnect, body: Data()) }

    /// The packet id a SUBACK answers, and its per-topic return codes.
    ///
    /// A return code >= 0x80 is a REFUSAL — in this deployment always an
    /// authorization decision, since the broker's only authorizer is the topic
    /// ACL. Refusals do not arrive as errors and do not arrive as silence, which
    /// is why reading this body is the difference between "the ACL has no row
    /// for this client" and an unexplained reconnect loop.
    ///
    /// Returns nil for a body too short to carry an id and at least one code.
    static func subackReturnCodes(_ body: Data) -> (packetID: UInt16, codes: [UInt8])? {
        guard body.count >= 3 else { return nil }
        let start = body.startIndex
        let id = UInt16(body[start]) << 8 | UInt16(body[start + 1])
        return (id, [UInt8](body[(start + 2)...]))
    }

    // --- inbound parsing ----------------------------------------------------

    /// Pulls one complete packet off the front of `buffer`, or returns nil when
    /// the buffer does not hold a whole one yet. A WebSocket frame may carry a
    /// partial packet, several packets, or both — hence the rolling buffer.
    /// What one call to `nextPacket` found at the head of the buffer.
    enum NextPacket: Equatable {
        case packet(MQTTPacket)
        /// A whole packet is not here yet. Keep the buffer and wait.
        case incomplete
        /// The stream cannot be parsed, or claims a packet larger than this
        /// client will accept. The caller must fail the connection — waiting is
        /// what turned a hostile length into an unbounded buffer.
        case malformed(reason: String)
    }

    /// The packet, when there is one. For call sites that genuinely only care —
    /// tests, and the fuzz target's decoder sweep. The RECEIVE path must switch
    /// over `NextPacket` exhaustively instead (see `ingest`): collapsing
    /// `.malformed` into "nothing yet" is precisely the bug the third case exists
    /// to prevent.
    static func packetIfAny(from buffer: inout Data) -> MQTTPacket? {
        if case .packet(let p) = nextPacket(from: &buffer) { return p }
        return nil
    }

    static func nextPacket(from buffer: inout Data) -> NextPacket {
        guard buffer.count >= 2 else { return .incomplete }
        let prefix = decodeLength(buffer, from: 1)
        guard case .complete(let remaining, let lengthBytes) = prefix else {
            return prefix == .malformed
                ? .malformed(reason: "remaining-length ran past four continuation bytes")
                : .incomplete
        }
        let total = 1 + lengthBytes + remaining
        // Checked against the CLAIM, before a single byte of it is buffered —
        // the point is to refuse the accumulation, not to notice it afterwards.
        guard total <= maxPacketBytes else {
            return .malformed(reason: "packet claims \(total) bytes, over the \(maxPacketBytes) limit")
        }
        guard buffer.count >= total else { return .incomplete }

        let header = buffer[buffer.startIndex]
        let bodyStart = buffer.startIndex + 1 + lengthBytes
        let body = Data(buffer[bodyStart..<(buffer.startIndex + total)])
        buffer.removeFirst(total)
        return .packet(MQTTPacket(header: header, body: body))
    }

    /// Decodes a PUBLISH body into topic / packet id (QoS > 0) / payload.
    static func parsePublish(_ p: MQTTPacket) -> (topic: String, packetID: UInt16?, payload: Data)? {
        let body = p.body
        guard body.count >= 2 else { return nil }
        let base = body.startIndex
        let topicLen = Int(body[base]) << 8 | Int(body[base + 1])
        guard body.count >= 2 + topicLen else { return nil }
        guard let topic = String(data: body[(base + 2)..<(base + 2 + topicLen)], encoding: .utf8) else { return nil }

        var cursor = base + 2 + topicLen
        var packetID: UInt16?
        let qos = (p.flags >> 1) & 0x03
        if qos > 0 {
            guard body.count >= (cursor - base) + 2 else { return nil }
            packetID = UInt16(body[cursor]) << 8 | UInt16(body[cursor + 1])
            cursor += 2
        }
        return (topic, packetID, Data(body[cursor...]))
    }

    /// CONNACK return code (0 = accepted).
    static func connackCode(_ p: MQTTPacket) -> UInt8? {
        guard p.body.count >= 2 else { return nil }
        return p.body[p.body.startIndex + 1]
    }

    /// PUBACK's two-byte packet id.
    ///
    /// This read used to live inline in `handle(_:)`, which is private and needs
    /// a socket to reach — so it was the one piece of inbound parsing that no
    /// test and no fuzz harness could call. Same bytes, same arithmetic, now in
    /// the section whose heading already promised "pure; unit-testable without
    /// a socket".
    static func pubackPacketID(_ body: Data) -> UInt16? {
        guard body.count >= 2 else { return nil }
        return UInt16(body[body.startIndex]) << 8 | UInt16(body[body.startIndex + 1])
    }
}

/// What to do with QoS-1 publishes still unacknowledged when a session comes up.
///
/// Replay exists so a message composed during a blip is not lost. But a publish
/// the broker REFUSES is never acknowledged, so it survives in the in-flight set
/// and is re-sent on the next CONNACK, and the next. EMQX runs
/// `deny_action = disconnect`, so each replay also kills the link that would
/// have carried everything else — one denied packet bricks the connection
/// permanently, and the loop feeds itself: connect, replay, denied, dropped,
/// repeat, with the backoff resetting every cycle because every connect
/// genuinely succeeded.
///
/// There is nothing to read that says a publish was refused — MQTT 3.1.1 has no
/// negative acknowledgement, and the broker simply closes. So the only available
/// signal is that the packet keeps not being acked, and the only safe response
/// is to stop sending it.
///
/// Pure, because getting it wrong is silent in both directions: too eager and a
/// real message is dropped, too patient and the app never connects again.
enum ReplayPolicy {

    /// Attempts allowed before a packet is abandoned. Well past any transient
    /// cause; after this the packet is the problem.
    static let maxReplays = 3

    /// Split in-flight publishes, by how many times each has already been sent,
    /// into those to re-send now and those to give up on.
    static func plan(attempts: [UInt16: Int]) -> (replay: [UInt16], abandon: [UInt16]) {
        var replay: [UInt16] = []
        var abandon: [UInt16] = []
        for (id, n) in attempts {
            if n >= maxReplays { abandon.append(id) } else { replay.append(id) }
        }
        return (replay.sorted(), abandon.sorted())
    }
}

// MARK: - Transport

/// MQTT over `URLSessionWebSocketTask`, with the app's SPKI pinning.
final class MQTTWireClient: MQTTBackend, @unchecked Sendable {

    enum MQTTError: LocalizedError {
        case connectionRefused(UInt8)
        case notConnected
        /// The byte stream cannot be parsed as MQTT, or claims a packet larger
        /// than `MQTTCodec.maxPacketBytes`. Terminal for the connection: there is
        /// no resynchronisation point in a length-prefixed stream once the length
        /// is untrustworthy, and continuing to buffer is the failure this
        /// replaced.
        case malformedStream(String)

        var errorDescription: String? {
            switch self {
            case .connectionRefused(let code):
                // 4 = bad username/password, 5 = not authorised: an expired or
                // consumed MQTT token. The caller refreshes and retries.
                return "MQTT connection refused by the broker (code \(code))"
            case .notConnected:
                return "MQTT is not connected"
            case .malformedStream(let reason):
                return "MQTT stream is unparseable: \(reason)"
            }
        }
    }

    /// Keepalive in seconds. EMQX drops a client that misses 1.5×; we ping at
    /// half, which also gives us a liveness signal on an otherwise idle link.
    /// MQTT keepalive, in seconds. `startPing` fires at half this.
    ///
    /// Was 30, so a ping every 15 s — four radio wakes a minute on an idle
    /// foreground connection, which on a phone is a battery cost paid for
    /// nothing. EMQX disconnects at 1.5x keepalive, so 60 s here means the
    /// broker notices a dead client within 90 s instead of 45. Nothing depends
    /// on the difference: presence has a retained Last-Will for exactly this,
    /// and the push bridge reads presence rather than liveness.
    private let keepAlive: UInt16 = 60

    private let queue = DispatchQueue(label: "mqtt.wire")
    private var session: URLSession?
    private var task: URLSessionWebSocketTask?
    private var pinning: TLSPinningDelegate?
    private var pingTimer: DispatchSourceTimer?

    private var buffer = Data()
    private var onEvent: ((MQTTEvent) -> Void)?
    private var connected = false          // CONNACK received
    private var closed = false             // terminal for this connection
    private var nextID: UInt16 = 1

    /// QoS-1 publishes awaiting PUBACK, re-sent (with DUP) after a reconnect so a
    /// message composed during a blip is not silently lost.
    private var unacked: [UInt16: (topic: String, payload: Data, retained: Bool, attempts: Int)] = [:]

    /// How many times one QoS-1 publish may be replayed across reconnects before
    /// it is abandoned.
    ///
    /// Replay exists so a message composed during a blip is not lost. But an
    /// UNDELIVERABLE publish — one the broker refuses on authorization — is
    /// never acknowledged, so it survives in `unacked` and is re-sent on the
    /// next CONNACK, and the next. The broker runs `deny_action = disconnect`,
    /// so each replay also kills the link that would have carried everything
    /// else. One denied packet bricks the connection permanently, and the loop
    /// feeds itself: connect, replay, denied, dropped, repeat, with the backoff
    /// resetting every cycle because every connect genuinely succeeded.
    ///
    /// See `ReplayPolicy` for the reasoning and the bound.
    /// Packets handed over before CONNACK; flushed in order once the session is up.
    private var pending: [Data] = []

    /// The clientID the queues above belong to. Replay is only ever valid for the
    /// identity that queued it — see `adoptIdentity`.
    private var sessionIdentity: String?

    /// Topic per in-flight SUBSCRIBE packet id, so a SUBACK can name what it
    /// refused. Without it a refusal has a return code and no subject, and the
    /// six causes have six different remedies.
    private var subscribeTopics: [UInt16: String] = [:]

    // MARK: MQTTBackend

    func connect(url: URL, clientID: String, username: String, password: String,
                 willTopic: String, willPayload: Data,
                 onEvent: @escaping (MQTTEvent) -> Void) {
        queue.async {
            self.teardown(notify: false)
            self.adoptIdentity(clientID)
            self.onEvent = onEvent
            self.closed = false
            self.connected = false
            self.buffer.removeAll()

            let pinning = TLSPinningDelegate()
            let session = URLSession(configuration: .default, delegate: pinning, delegateQueue: nil)
            // "mqtt" is the subprotocol MQTT-over-WebSocket mandates; EMQX
            // rejects the upgrade without it.
            let task = session.webSocketTask(with: url, protocols: ["mqtt"])
            self.pinning = pinning
            self.session = session
            self.task = task

            pinning.setOnClose { [weak self] error in
                self?.queue.async { self?.fail(error) }
            }

            task.resume()
            self.receiveLoop()
            self.send(MQTTCodec.connect(
                clientID: clientID, username: username, password: password,
                willTopic: willTopic, willPayload: willPayload, willRetain: true,
                keepAlive: self.keepAlive, cleanSession: false))
        }
    }

    func subscribe(_ topic: String, qos: Int) {
        queue.async {
            let id = self.takeID()
            self.subscribeTopics[id] = topic
            self.enqueue(MQTTCodec.subscribe(topic: topic, qos: qos, packetID: id))
        }
    }

    func unsubscribe(_ topic: String) {
        queue.async {
            let id = self.takeID()
            self.enqueue(MQTTCodec.unsubscribe(topic: topic, packetID: id))
        }
    }

    /// Publish a frame. `onWrite`, when given, fires once the frame has actually
    /// been handed to the socket — `true` — or could not be, `false`, because
    /// there is no session yet and it was buffered for the next CONNACK.
    ///
    /// Callers do not normally care: a publish is fire-and-forget and `unacked`
    /// replays it. ONE caller does. Going to the background, the app publishes
    /// "I am offline" and holds a `beginBackgroundTask` assertion so iOS cannot
    /// suspend it mid-send — and had nothing to wait ON, so it released the
    /// assertion after `queue.async` had been *scheduled*, not after the bytes
    /// left. When iOS won that race the broker kept the device marked online,
    /// the push-bridge skipped it as reachable, and the message the user was
    /// waiting for produced no notification at all. Not a delay: the wake
    /// decision is made once, at publish time, and is never revisited.
    func publish(_ topic: String, payload: Data, qos: Int, retained: Bool,
                 onWrite: ((Bool) -> Void)? = nil) {
        queue.async {
            if qos > 0 {
                let id = self.takeID()
                self.unacked[id] = (topic, payload, retained, 0)
                self.enqueue(MQTTCodec.publish(topic: topic, payload: payload, qos: qos,
                                               retained: retained, packetID: id),
                             replayedFromUnacked: true, then: onWrite)
            } else {
                self.enqueue(MQTTCodec.publish(topic: topic, payload: payload, qos: 0,
                                               retained: retained, packetID: nil),
                             then: onWrite)
            }
        }
    }

    func disconnect() {
        queue.async {
            if self.connected { self.send(MQTTCodec.disconnect()) }
            self.teardown(notify: false)
        }
    }

    /// In-flight QoS-1 publishes. Diagnostics, and what `adoptIdentity` is
    /// asserted on.
    var inFlightPublishCount: Int { queue.sync { unacked.count } }

    // MARK: Internals (all on `queue`)

    /// Take `clientID` as this connection's identity, dropping anything queued
    /// for a DIFFERENT one.
    ///
    /// Replay is the whole point of `unacked`: a message composed during a blip
    /// is re-sent when the socket comes back. It is only ever valid for the
    /// identity that queued it, though, and a profile switch reuses this object
    /// with a new one. What was left over then was a DUP publish onto the
    /// PREVIOUS profile's topic — `u/{oldPk}/presence`, queued by the graceful
    /// offline publish that `MQTTService.disconnect()` sends a moment before it
    /// tears the socket down and so can never be acked.
    ///
    /// That is not a packet the broker ignores. EMQX runs `deny_action =
    /// disconnect` (infra/deploy/emqx/emqx.conf), so one publish to a topic this
    /// key has no grant on drops the connection — immediately after CONNACK,
    /// before anything else can happen. The reconnect re-sends it and is dropped
    /// again, which is a loop nothing times out of and nothing explains: the
    /// broker's own log calls it an authorization failure on a topic belonging to
    /// an account the user is no longer signed in as.
    /// Called by `connect(...)`, and directly by the tests — the loop it prevents
    /// needs a broker to reproduce, but the queue it empties does not.
    func adoptIdentity(_ clientID: String) {
        if clientID != sessionIdentity {
            unacked.removeAll()
            pending.removeAll()
        }
        sessionIdentity = clientID
    }

    private func takeID() -> UInt16 {
        let id = nextID
        nextID = nextID == UInt16.max ? 1 : nextID + 1
        return id
    }

    /// Send now if the session is up, otherwise hold until CONNACK.
    ///
    /// A buffered packet reports `false` rather than waiting: `then` answers
    /// "did this reach the socket", and a frame parked for a reconnect that may
    /// never come has not. Holding an iOS background assertion open on that
    /// promise is how a five-second grace becomes a watchdog kill.
    private func enqueue(_ packet: Data, replayedFromUnacked: Bool = false,
                         then: ((Bool) -> Void)? = nil) {
        if connected {
            send(packet, then: then)
            return
        }
        // A QoS-1 publish is ALREADY in `unacked`, and the CONNACK handler
        // replays that with DUP set. Queueing it here as well sent the same
        // packet id twice on every reconnect — 164 kB for a first message
        // composed offline, since an `init` is ~82 kB — and charged the frame a
        // `ReplayPolicy.maxReplays` attempt it never earned, so three ordinary
        // reconnects retired it as though the broker had been refusing it.
        //
        // Dropping the duplicate is also strictly MORE reliable, not merely
        // equivalent: `teardown` clears `pending` while `unacked` survives
        // (cleared only by `adoptIdentity`), so the copy removed here is the one
        // that a socket death loses anyway.
        //
        // `pending` is left holding what it was built for: QoS-0 publishes and
        // control frames (SUBSCRIBE / UNSUBSCRIBE), neither of which has a retry
        // path of its own.
        if !replayedFromUnacked { pending.append(packet) }
        then?(false)
    }

    private func send(_ packet: Data, then: ((Bool) -> Void)? = nil) {
        guard let task else { then?(false); return }
        task.send(.data(packet)) { [weak self] error in
            if let error { self?.queue.async { self?.fail(error) } }
            then?(error == nil)
        }
    }

    private func receiveLoop() {
        guard let task else { return }
        task.receive { [weak self] result in
            guard let self else { return }
            self.queue.async {
                switch result {
                case .failure(let error):
                    self.fail(error)
                case .success(let message):
                    switch message {
                    case .data(let data): self.ingest(data)
                    case .string(let s): self.ingest(Data(s.utf8))   // not expected; MQTT is binary
                    @unknown default: break
                    }
                    guard !self.closed else { return }
                    self.receiveLoop()
                }
            }
        }
    }

    private func ingest(_ data: Data) {
        buffer.append(data)
        loop: while true {
            switch MQTTCodec.nextPacket(from: &buffer) {
            case .packet(let packet):
                handle(packet)
            case .incomplete:
                break loop
            case .malformed(let reason):
                // The stream is not recoverable, so the connection goes. Waiting
                // instead — which is what `nil` used to mean here — is how a
                // five-continuation-byte length wedged the client permanently:
                // nothing parsed, `buffer` grew unbounded, and the ping timer
                // kept reporting a healthy link.
                fail(MQTTError.malformedStream(reason))
                return
            }
        }
    }

    private func handle(_ packet: MQTTPacket) {
        switch packet.type {
        case .connack:
            guard let code = MQTTCodec.connackCode(packet) else { return }
            guard code == 0 else { fail(MQTTError.connectionRefused(code)); return }
            connected = true
            startPing()
            // Re-send anything that was in flight when the last session died,
            // then drain what was queued while connecting.
            //
            // Bounded, and reported. An unbounded replay of a packet the broker
            // refuses is a connection that can never come up again — see
            // `maxReplays`. Nothing said a replay was even happening, which is
            // why a self-inflicted loop looked like a network fault.
            let plan = ReplayPolicy.plan(attempts: unacked.mapValues { $0.attempts })
            for id in plan.abandon {
                guard let p = unacked.removeValue(forKey: id) else { continue }
                onEvent?(.publishAbandoned(topic: p.topic, attempts: p.attempts))
            }
            for id in plan.replay {
                guard let p = unacked[id] else { continue }
                unacked[id]?.attempts = p.attempts + 1
                onEvent?(.publishReplayed(topic: p.topic, attempt: p.attempts + 1))
                send(MQTTCodec.publish(topic: p.topic, payload: p.payload, qos: 1,
                                       retained: p.retained, packetID: id, dup: true))
            }
            let queued = pending
            pending.removeAll()
            for packet in queued { send(packet) }
            onEvent?(.connected)

        case .publish:
            guard let (topic, packetID, payload) = MQTTCodec.parsePublish(packet) else { return }
            // QoS 1 inbound: acknowledge so EMQX stops redelivering.
            if let packetID, (packet.flags >> 1) & 0x03 == 1 {
                send(MQTTCodec.puback(packetID: packetID))
            }
            onEvent?(.message(topic: topic, payload: payload))

        case .puback:
            guard let id = MQTTCodec.pubackPacketID(packet.body) else { return }
            unacked.removeValue(forKey: id)

        case .suback:
            // A broker that REFUSES a subscription does not close with an error
            // and does not fail to answer: it SUBACKs with return code 0x80.
            // Ignoring the body meant an ACL denial looked exactly like success
            // — the app sat there subscribed to nothing, receiving nothing, with
            // a clean log. Under `deny_action = disconnect` the broker ALSO drops
            // the link, which arrives here as a bare POSIX 57 "Socket is not
            // connected" on the next write: a reconnect loop whose real cause is
            // a missing `mqtt_acl` row and which says so nowhere.
            //
            // The server-side bot has checked this since the outage that taught
            // it to (bot.ts subscribeConversation). This client never did.
            guard let ack = MQTTCodec.subackReturnCodes(packet.body) else { return }
            let topic = subscribeTopics.removeValue(forKey: ack.packetID)
            for code in ack.codes where code >= 0x80 {
                onEvent?(.subscribeRefused(topic: topic ?? "(unknown topic)", code: code))
            }

        case .unsuback, .pingresp:
            break   // nothing to do

        default:
            break
        }
    }

    private func startPing() {
        pingTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        let interval = Double(keepAlive) / 2
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            guard let self, self.connected else { return }
            self.send(MQTTCodec.pingreq())
        }
        timer.resume()
        pingTimer = timer
    }

    /// Terminal failure for this connection: report once, then tear down. The
    /// caller (MQTTService) owns reconnect + token rotation.
    private func fail(_ error: Error) {
        guard !closed else { return }
        let handler = onEvent
        teardown(notify: false)
        handler?(.disconnected(error))
    }

    private func teardown(notify: Bool) {
        closed = true
        connected = false
        pingTimer?.cancel()
        pingTimer = nil
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        session?.invalidateAndCancel()
        session = nil
        pinning = nil
        pending.removeAll()
        subscribeTopics.removeAll()
        if notify { onEvent?(.disconnected(nil)) }
    }
}
