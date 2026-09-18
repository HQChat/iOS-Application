import Foundation
import CryptoKit
import Security

/// Server endpoints + TLS pinning, extracted from the retired `WebSocketManager`
/// (Phase 4 of the MQTT migration — see deploy/EXTRACTION_PLAN.md). Nothing in
/// the app speaks the old `/ws` protocol any more: messaging and presence ride
/// MQTT-over-WSS, everything else is REST. Both paths pin the same SPKI hashes.

/// Resolves the server endpoints. Override per build/environment with Info.plist
/// keys (e.g. via an xcconfig); production is the fallback so a misconfigured
/// build never silently points somewhere else.
enum ServerConfig {

    /// The home server of the profile currently signed in, set by ChatSession
    /// before it connects. A profile is an identity + a home server, so this
    /// moves with the active profile; nil means "use the build default".
    static var activeHost: String?

    /// The public origin every endpoint below is derived from. Override per
    /// build with the Info.plist key `ServerHost` (bare host, no scheme).
    static var host: String {
        if let h = activeHost, !h.isEmpty { return h }
        if let s = Bundle.main.object(forInfoDictionaryKey: "ServerHost") as? String, !s.isEmpty {
            return s
        }
        return Deployment.serverHost
    }

    private static var httpsOrigin: String { "https://\(host)" }

    /// The `/auth/*` door prefix — origin PLUS the literal path segment, so
    /// callers pass `free/init`, `paid/verify`, `refresh`. Override: `ServerAuthURL`.
    ///
    /// This is a PATH PREFIX, not "wherever the auth service lives". The auth
    /// service also owns routes that nginx mounts at the ROOT — `/claim/*` and
    /// the EMQX hook `/mqtt/authn` — and none of them are reachable by appending
    /// to this. Use `claimBaseURL` for those. Reading this name as "the auth
    /// service's base URL" is what sent every claim to `/auth/claim/start`, which
    /// is a 404 the user met as "Couldn't reach the server (404)".
    static var authBaseURL: URL {
        if let s = Bundle.main.object(forInfoDictionaryKey: "ServerAuthURL") as? String,
           !s.isEmpty, let url = URL(string: s) { return url }
        return URL(string: "\(httpsOrigin)/auth")!
    }

    /// Subscription claim (`/claim/start`, `/claim/verify`). Served by the auth
    /// service but mounted at the root by nginx, hence the origin rather than
    /// `authBaseURL`. Override: `ServerClaimURL`, for a deployment that puts auth
    /// on its own host.
    static var claimBaseURL: URL {
        if let s = Bundle.main.object(forInfoDictionaryKey: "ServerClaimURL") as? String,
           !s.isEmpty, let url = URL(string: s) { return url }
        return URL(string: httpsOrigin)!
    }

    /// App-API (REST directory/friends/push/account). Override: `ServerAPIURL`.
    static var apiBaseURL: URL {
        if let s = Bundle.main.object(forInfoDictionaryKey: "ServerAPIURL") as? String,
           !s.isEmpty, let url = URL(string: s) { return url }
        return URL(string: httpsOrigin)!
    }

    /// MQTT-over-WSS endpoint (nginx → EMQX). Override: `ServerMQTTURL`.
    static var mqttURL: URL {
        if let s = Bundle.main.object(forInfoDictionaryKey: "ServerMQTTURL") as? String,
           !s.isEmpty, let url = URL(string: s) { return url }
        return URL(string: "wss://\(host)/mqtt")!
    }

    /// The origin as the user typed/stored it per profile, for display.
    static var displayOrigin: String { httpsOrigin }
}

/// Pins the server's SPKI (SHA-256, base64) from Info.plist `ServerPinnedSPKIHashes`.
/// Used by AuthService, APIClient and the MQTT transport. Fails closed when pins
/// are configured; with none configured it still requires valid system trust.
final class TLSPinningDelegate: NSObject, URLSessionDelegate, URLSessionWebSocketDelegate, @unchecked Sendable {

    private let pins: Set<Data>

    /// Result of the WebSocket handshake, recorded whether or not anyone is
    /// currently awaiting it (the delegate callback can land first).
    private enum Handshake {
        case open
        case failed(Error)
    }

    private let lock = NSLock()
    private var handshake: Handshake?
    private var waiter: CheckedContinuation<Void, Error>?
    /// Called on the first terminal outcome, so a transport can react without
    /// polling (the MQTT client uses it to surface a drop as `.disconnected`).
    private var onClose: ((Error) -> Void)?

    override init() {
        // Info.plist wins so a build can pin without touching source; otherwise
        // the deployment's own list (empty by default — see Deployment).
        let raw = (Bundle.main.object(forInfoDictionaryKey: "ServerPinnedSPKIHashes") as? [String])
            ?? Deployment.pinnedSPKIHashes
        self.pins = Set(raw.compactMap { Data(base64Encoded: $0) })
        #if DEBUG
        if pins.isEmpty {
            print("🔓 TLS pinning: no pins configured — system trust only (MAS-3)")
        }
        #endif
        super.init()
    }

    // MARK: - Handshake signalling

    /// Suspends until the WebSocket handshake opens, or throws the transport
    /// error that stopped it (`.notConnectedToInternet` in airplane mode).
    func waitUntilOpen(timeout: TimeInterval) async throws {
        let timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            guard !Task.isCancelled else { return }
            self?.settle(.failed(URLError(.timedOut)))
        }
        defer { timeoutTask.cancel() }

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            lock.lock()
            if let outcome = handshake {
                lock.unlock()
                switch outcome {
                case .open: cont.resume()
                case .failed(let error): cont.resume(throwing: error)
                }
                return
            }
            waiter = cont
            lock.unlock()
        }
    }

    /// Register a one-shot callback for a transport failure/close.
    func setOnClose(_ handler: @escaping (Error) -> Void) {
        lock.lock()
        let alreadyFailed: Error?
        if case .failed(let e) = handshake { alreadyFailed = e } else { alreadyFailed = nil }
        onClose = handler
        lock.unlock()
        if let alreadyFailed { handler(alreadyFailed) }
    }

    /// Records the first terminal handshake outcome and wakes any waiter.
    /// Subsequent calls are ignored, so a close following an open is harmless.
    private func settle(_ outcome: Handshake) {
        lock.lock()
        guard handshake == nil else { lock.unlock(); return }
        handshake = outcome
        let cont = waiter
        waiter = nil
        let close = onClose
        lock.unlock()

        switch outcome {
        case .open: cont?.resume()
        case .failed(let error):
            cont?.resume(throwing: error)
            close?(error)
        }
    }

    /// A transport that opened successfully and later dropped: the handshake is
    /// already settled `.open`, so route the close to the callback directly.
    private func reportClose(_ error: Error) {
        lock.lock()
        let opened: Bool
        if case .open = handshake { opened = true } else { opened = false }
        let close = onClose
        lock.unlock()
        if opened { close?(error) } else { settle(.failed(error)) }
    }

    func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didOpenWithProtocol protocol: String?
    ) {
        settle(.open)
    }

    func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didCloseWith closeCode: URLSessionWebSocketTask.CloseCode,
        reason: Data?
    ) {
        reportClose(URLError(.networkConnectionLost))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        reportClose(error ?? URLError(.networkConnectionLost))
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // 1. Always require the chain to be valid under system trust first. This
        //    rejects expired/untrusted/hostname-mismatched certs regardless of pins.
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 2. No pins configured → default handling (valid system trust already
        //    confirmed above). No downgrade; just no extra pinning.
        if pins.isEmpty {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }

        // 3. Pins configured → at least one cert in the chain must match. Fail closed.
        if Self.chainMatchesAnyPin(trust: trust, pins: pins) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// True if any certificate in the chain has an SPKI whose SHA-256 is pinned.
    static func chainMatchesAnyPin(trust: SecTrust, pins: Set<Data>) -> Bool {
        let certs: [SecCertificate]
        if #available(iOS 15.0, macOS 12.0, *) {
            certs = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        } else {
            certs = (0..<SecTrustGetCertificateCount(trust)).compactMap {
                SecTrustGetCertificateAtIndex(trust, $0)
            }
        }
        for cert in certs {
            if let spki = spkiSHA256(for: cert), pins.contains(spki) {
                return true
            }
        }
        return false
    }

    /// Internal rather than private so `tests/TLSPinningTests.swift` can hold the
    /// reconstruction below to what OpenSSL actually emits. The header table is
    /// hand-written; a wrong entry means the pin never matches, the app fails
    /// closed, and the symptom is "cannot connect" with nothing naming the cause.
    ///
    /// SHA-256 over the DER SubjectPublicKeyInfo, reconstructed by prepending the
    /// standard ASN.1 header for the key's type + size to the raw key bytes
    /// returned by SecKeyCopyExternalRepresentation.
    static func spkiSHA256(for cert: SecCertificate) -> Data? {
        guard let key = SecCertificateCopyKey(cert),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let attrs = SecKeyCopyAttributes(key) as? [CFString: Any],
              let keyType = attrs[kSecAttrKeyType] as? String,
              let bits = attrs[kSecAttrKeySizeInBits] as? Int,
              let header = asn1Header(keyType: keyType, sizeInBits: bits) else {
            return nil
        }
        var spki = Data(header)
        spki.append(raw)
        return Data(SHA256.hash(data: spki))
    }

    /// ASN.1 SubjectPublicKeyInfo headers for the key types we expect from the
    /// origin (RSA 2048/4096, EC P-256/P-384). Returns nil for anything else, in
    /// which case that cert simply can't match a pin (and others in the chain are
    /// tried).
    static func asn1Header(keyType: String, sizeInBits: Int) -> [UInt8]? {
        let rsa = kSecAttrKeyTypeRSA as String
        let ec = kSecAttrKeyTypeECSECPrimeRandom as String
        switch (keyType, sizeInBits) {
        case (rsa, 2048):
            return [0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0f,0x00]
        case (rsa, 4096):
            return [0x30,0x82,0x02,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x02,0x0f,0x00]
        case (ec, 256):
            return [0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]
        case (ec, 384):
            return [0x30,0x76,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2b,0x81,0x04,0x00,0x22,0x03,0x62,0x00]
        default:
            return nil
        }
    }
}
