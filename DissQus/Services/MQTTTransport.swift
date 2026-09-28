//
//  MQTTTransport.swift
//  DissQus (shared macOS + iOS)
//
//  The byte pipes MQTT runs over. MQTTWireClient owns the MQTT session — the
//  codec, CONNACK, replay, keepalive — and hands the bytes to one of these:
//
//    WSSTransport  MQTT over WebSocket over TLS, through nginx and Cloudflare,
//                  with the app's SPKI pinning. The original path, and the
//                  permanent fallback.
//    HQNTransport  MQTT over raw TCP, inside hqn/1 (NoiseHQN.swift): a hybrid
//                  X25519 + HQC-256 Noise handshake to noise-gw, whose FIRST
//                  flight already carries the CONNECT. No WebSocket upgrade and
//                  no TLS handshake: a connect is TCP's round trip plus one.
//
//  The seam is deliberately the byte stream, not MQTT: nothing above this file
//  knows which one it is using, so the session logic is tested once, and a
//  transport is only a transport.
//

import Foundation
import Network

enum TransportError: LocalizedError {
    case notOpen
    var errorDescription: String? { "the transport is not open" }
}

/// A bidirectional byte stream for MQTT. Every callback may arrive on any
/// queue; the owner hops to its own.
protocol ByteTransport: AnyObject {
    /// Open the link. `opening` is the first bytes of the stream — the MQTT
    /// CONNECT — which a transport may carry inside its own handshake.
    func start(opening: Data,
               onReceive: @escaping (Data) -> Void,
               onClose: @escaping (Error?) -> Void)
    /// Queue bytes; `completion(nil)` once they are handed to the socket.
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    /// Tear down without reporting a close.
    func cancel()
}

// MARK: - WSS

final class WSSTransport: ByteTransport {
    private let url: URL
    private var session: URLSession?
    private var task: URLSessionWebSocketTask?
    private var pinning: TLSPinningDelegate?
    private var onReceive: ((Data) -> Void)?
    private var onClose: ((Error?) -> Void)?

    init(url: URL) { self.url = url }

    func start(opening: Data, onReceive: @escaping (Data) -> Void, onClose: @escaping (Error?) -> Void) {
        self.onReceive = onReceive
        self.onClose = onClose
        let pinning = TLSPinningDelegate()
        let session = URLSession(configuration: .default, delegate: pinning, delegateQueue: nil)
        // "mqtt" is the subprotocol MQTT-over-WebSocket mandates; EMQX rejects
        // the upgrade without it.
        let task = session.webSocketTask(with: url, protocols: ["mqtt"])
        self.pinning = pinning
        self.session = session
        self.task = task
        pinning.setOnClose { [weak self] error in self?.onClose?(error) }
        task.resume()
        receiveLoop()
        send(opening) { _ in }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard let task else { completion(TransportError.notOpen); return }
        task.send(.data(data)) { [weak self] error in
            if let error { self?.onClose?(error) }
            completion(error)
        }
    }

    private func receiveLoop() {
        guard let task else { return }
        task.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.onClose?(error)
            case .success(let message):
                switch message {
                case .data(let data): self.onReceive?(data)
                case .string(let s): self.onReceive?(Data(s.utf8))   // not expected; MQTT is binary
                @unknown default: break
                }
                if self.task != nil { self.receiveLoop() }
            }
        }
    }

    func cancel() {
        onReceive = nil
        onClose = nil
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        session?.invalidateAndCancel()
        session = nil
        pinning = nil
    }
}

// MARK: - HQN (raw TCP + hqn/1)

final class HQNTransport: ByteTransport {
    enum HQNError: LocalizedError {
        case handshakeFailed
        case closedByPeer
        var errorDescription: String? {
            switch self {
            case .handshakeFailed: return "hqn/1 handshake failed"
            case .closedByPeer: return "hqn/1 connection closed by the gateway"
            }
        }
    }

    private let endpoint: HQNEndpoint
    private let queue = DispatchQueue(label: "mqtt.hqn")
    private var connection: NWConnection?
    private var initiator: NoiseHQN.Initiator?
    private var transport: NoiseHQN.Transport?
    private var reader = NoiseHQN.FrameReader()
    /// Written before msg2 arrived; sealed once the transport keys exist.
    private var queued: [(Data, (Error?) -> Void)] = []
    private var onReceive: ((Data) -> Void)?
    private var onClose: ((Error?) -> Void)?
    private var closed = false
    /// Fires once, when msg2 has been read and the stream is encrypted — the
    /// signal the fallback's deadline is judged against.
    var onEstablished: (() -> Void)?

    init(endpoint: HQNEndpoint) { self.endpoint = endpoint }

    func start(opening: Data, onReceive: @escaping (Data) -> Void, onClose: @escaping (Error?) -> Void) {
        queue.async { self.begin(opening: opening, onReceive: onReceive, onClose: onClose) }
    }

    private func begin(opening: Data, onReceive: @escaping (Data) -> Void, onClose: @escaping (Error?) -> Void) {
        self.onReceive = onReceive
        self.onClose = onClose
        // The newest key id is the one to use; older ones stay pinned only so a
        // server mid-rotation is still reachable.
        guard let key = endpoint.keys.max(by: { $0.keyID < $1.keyID }) else { return close(HQNError.handshakeFailed) }
        let first: Data
        do {
            // The real HQC-256, from the native library. NoiseHQN takes the KEM
            // as a parameter so the protocol file stays pure CryptoKit.
            let initiator = try NoiseHQN.Initiator(server: key, encapsulate: { pk in
                let r = try HQCService.encapsulate(publicKey: pk)
                return (r.0, r.1)
            })
            self.initiator = initiator
            // HQC-256 encapsulation happens here, on this transport's queue.
            let msg1 = try initiator.writeMessage1(payload: opening)
            first = Data([NoiseHQN.version, key.keyID]) + (try NoiseHQN.frame(msg1))
        } catch {
            return close(HQNError.handshakeFailed)
        }

        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = 10
        let conn = NWConnection(host: NWEndpoint.Host(endpoint.host),
                                port: NWEndpoint.Port(rawValue: endpoint.port)!,
                                using: NWParameters(tls: nil, tcp: tcp))
        connection = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                conn.send(content: first, completion: .contentProcessed { [weak self] error in
                    if let error { self?.queue.async { self?.close(error) } }
                })
                self.receive()
            case .failed(let error):
                self.close(error)
            case .waiting(let error):
                // No route yet (captive portal, a firewall silently dropping
                // SYNs). Waiting is the fallback's to judge; report it as a
                // failure so the next transport gets its turn now.
                self.close(error)
            case .cancelled:
                self.close(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func receive() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.reader.push(data)
                do {
                    while let frame = self.reader.next() {
                        if let t = self.transport {
                            self.onReceive?(try t.receive.decrypt(ad: Data(), frame))
                        } else {
                            guard let initiator = self.initiator else { throw HQNError.handshakeFailed }
                            self.transport = try initiator.readMessage2(frame).transport
                            self.initiator = nil
                            self.onEstablished?()
                            self.onEstablished = nil
                            for (bytes, done) in self.queued { self.write(bytes, completion: done) }
                            self.queued.removeAll()
                        }
                    }
                } catch {
                    return self.close(HQNError.handshakeFailed)
                }
            }
            if let error { return self.close(error) }
            if isComplete { return self.close(HQNError.closedByPeer) }
            self.receive()
        }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async {
            guard !self.closed else { return completion(TransportError.notOpen) }
            if self.transport == nil { self.queued.append((data, completion)) }
            else { self.write(data, completion: completion) }
        }
    }

    /// Seal and write. Small MQTT packets become ONE frame, so a publish is one
    /// segment on the wire rather than a header and a payload in two.
    private func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard let t = transport, let conn = connection else { return completion(TransportError.notOpen) }
        do {
            let wire = try NoiseHQN.sealFrames(t.send, data)
            conn.send(content: wire, completion: .contentProcessed { [weak self] error in
                if let error { self?.queue.async { self?.close(error) } }
                completion(error)
            })
        } catch {
            close(error)
            completion(error)
        }
    }

    private func close(_ error: Error?) {
        guard !closed else { return }
        closed = true
        let report = onClose
        teardown()
        report?(error ?? HQNError.closedByPeer)
    }

    func cancel() {
        queue.async {
            self.closed = true
            self.teardown()
        }
    }

    private func teardown() {
        onReceive = nil
        onClose = nil
        onEstablished = nil
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        connection = nil
        for (_, done) in queued { done(TransportError.notOpen) }
        queued.removeAll()
    }
}

// MARK: - Choosing one

enum MQTTTransports {
    /// The transport for an endpoint URL: `hqn://` needs the pinned keys for
    /// that host (ServerConfig.hqnEndpoint); anything else is WSS.
    static func make(for url: URL) -> ByteTransport {
        if url.scheme == "hqn", let ep = ServerConfig.hqnEndpoint,
           ep.host == url.host, Int(ep.port) == url.port {
            return HQNTransport(endpoint: ep)
        }
        return WSSTransport(url: url)
    }
}

// MARK: - Which transport to try, and for how long

/// The order to try transports in, per network, and how long hqn/1 gets before
/// the client gives up on it and uses WSS.
///
/// SEQUENTIAL, never parallel. Two CONNECTs with the same client id are a
/// session TAKEOVER at the broker — the second kicks the first — and each
/// carries a single-use signed proof. So an attempt runs to success or failure
/// before the next begins, and each attempt signs its own CONNECT.
///
/// Remembered per network kind: a network that blocks the gateway's port
/// (hotel Wi-Fi, some corporate networks) costs one deadline, then goes
/// straight to WSS until `rememberFor` passes and hqn/1 is probed again. A
/// success on hqn/1 clears that at once.
///
/// Pure apart from its lock, with the clock injected, so the policy is tested
/// without a network.
final class TransportSelector: @unchecked Sendable {
    enum Kind: String, Equatable { case hqn, wss }

    struct Attempt: Equatable {
        let kind: Kind
        let url: URL
        /// How long this attempt may take before the next one starts. Nil for
        /// the last resort, which gets the transport's own timeouts.
        let deadline: TimeInterval?
    }

    static let shared = TransportSelector()

    /// How long a network that failed hqn/1 goes straight to WSS.
    let rememberFor: TimeInterval
    /// The hqn/1 deadline: twice the last successful hqn connect, clamped.
    /// msg1 is ~14.7 kB — past a 10-segment initial window — so the floor is
    /// generous; the ceiling bounds what a blackholed port costs.
    let minDeadline: TimeInterval
    let maxDeadline: TimeInterval
    /// Remote and local switches. Remote comes from `/auth/transport` (via
    /// ServerConfig.hqnEndpoint); this one is the local debug toggle.
    var hqnAllowed: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _hqnAllowed }
        set { lock.lock(); _hqnAllowed = newValue; lock.unlock() }
    }

    private let lock = NSLock()
    private var _hqnAllowed = true
    private var wssWinnerUntil: [String: Date] = [:]
    private var lastHQNConnect: TimeInterval?
    private(set) var stats: [Kind: (ok: Int, failed: Int)] = [:]

    init(rememberFor: TimeInterval = 3600, minDeadline: TimeInterval = 1.5, maxDeadline: TimeInterval = 4) {
        self.rememberFor = rememberFor
        self.minDeadline = minDeadline
        self.maxDeadline = maxDeadline
    }

    /// The attempts for this connect, in order.
    func plan(hqn: HQNEndpoint?, wss: URL, network: String, now: Date = Date()) -> [Attempt] {
        lock.lock(); defer { lock.unlock() }
        let last = Attempt(kind: .wss, url: wss, deadline: nil)
        guard _hqnAllowed, let hqn else { return [last] }
        if let until = wssWinnerUntil[network], until > now { return [last] }
        let deadline = min(maxDeadline, max(minDeadline, 2 * (lastHQNConnect ?? minDeadline)))
        return [Attempt(kind: .hqn, url: hqn.url, deadline: deadline), last]
    }

    /// What an attempt came to. `seconds` is start → CONNACK for a success.
    func record(_ kind: Kind, succeeded: Bool, seconds: TimeInterval?, network: String, now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        var s = stats[kind] ?? (0, 0)
        if succeeded { s.ok += 1 } else { s.failed += 1 }
        stats[kind] = s
        guard kind == .hqn else { return }
        if succeeded {
            wssWinnerUntil[network] = nil
            if let seconds { lastHQNConnect = seconds }
        } else {
            wssWinnerUntil[network] = now.addingTimeInterval(rememberFor)
        }
    }
}
