import Foundation
import CryptoKit

/// Client side of the REST HQC-KEM handshake against the auth server (Phase 1 of
/// the MQTT migration — see deploy/EXTRACTION_PLAN.md). Replaces the WS
/// AUTH_INIT/AUTH_CHALLENGE/AUTH_VERIFY exchange:
///
///   POST /auth/{free,paid}/init   { pk }           -> { ct }
///   (decapsulate ct -> ss; proof = HKDF(ss,"auth"))
///   POST /auth/{free,paid}/verify { pk, solution } -> { scope, sessionToken, … }
///   POST /auth/refresh (Bearer session)            -> { mqttToken, mqttExpiresAt }
///
/// TWO DOORS. The full door grants the whole app; the free door grants a session
/// that can talk to the helper bot and nothing else. We always knock on the full
/// door first and fall back.
///
/// The full door used to be the PAID door — it admitted only a key bound to a
/// live subscription and refused everything else with 402. There is no
/// subscription now and an ordinary server never answers 402, but this keeps
/// handling it, deliberately: that is what lets a current build keep working
/// against a server that has not been updated yet. Its wire name is still
/// "paid" for the same reason.
///
/// The `sessionToken` is a multi-use REST bearer (APIClient + refresh).
///
/// The MQTT CONNECT password is a v1 proof (MQTTConnectProof.swift): at sign-in
/// and on every refresh we register the public half of a fresh, in-memory
/// Ed25519 key, and each CONNECT is signed locally — no round trip, nothing
/// reusable on the wire. EMQX force-disconnects when the key expires; the next
/// connect refreshes. `mqttToken` is the pre-v1 bearer, used only against a
/// server that does not hand back a key id.
/// Transport is TLS (HTTPS) with the same SPKI pinning as the WebSocket path.
actor AuthService {

    /// Which door minted the session. Mirrors the server's `SessionScope`:
    /// `premium` has the whole friend graph, `free` has the helper bot and its
    /// own presence. On any ordinary server every session is `premium`; a `free`
    /// one means a private (`allowlist`) deployment turned the full door down.
    enum Scope: String {
        case free
        case premium
    }

    enum Door: String {
        case free
        case paid
    }

    struct Session {
        let pk: String
        /// This identity's client id — `sha256(lowercase-hex(pk))`. What the
        /// broker connects us as, and what every peer sees as our `sender`.
        /// Derived locally rather than taken from the response: the server's
        /// answer is checked against it, not trusted as it.
        var id: String { PeerID.from(publicKeyHex: pk) }
        let username: String?
        var scope: Scope
        let sessionToken: String
        var mqttToken: String
        /// Absolute expiry of `mqttToken` (unix seconds). EMQX force-disconnects
        /// at this time; refresh a little before to avoid a reconnect blip.
        var mqttExpiresAt: TimeInterval
        /// The id the server gave our registered signing key, and when that key
        /// expires (server clock). Nil against a server that predates v1.
        var mqttKeyID: String? = nil
        var mqttKeyExpiresAt: TimeInterval? = nil
    }

    enum AuthError: LocalizedError {
        case notAuthenticated
        case badResponse(Int, String)
        case decapsulationFailed
        case malformedChallenge

        var errorDescription: String? {
            switch self {
            case .notAuthenticated: return "Not authenticated"
            case .badResponse(let code, let msg): return "Auth server error \(code): \(msg)"
            case .decapsulationFailed: return "Failed to decapsulate the KEM challenge"
            case .malformedChallenge: return "Malformed challenge from the auth server"
            }
        }
    }

    private var current: Session?
    /// The private half of the key registered as `current.mqttKeyID`. Memory
    /// only, and replaced on every refresh: every launch signs in afresh, so
    /// there is nothing a Keychain copy would ever be read back for.
    private var mqttSigner: Curve25519.Signing.PrivateKey?
    /// Server clock minus ours, from the last `serverTime`. The proof's
    /// timestamp is judged by the server within ±60 s, and a phone's clock can
    /// be further off than that.
    private var clockOffset: TimeInterval = 0
    /// Refresh when the key has less than this left, rather than connect with a
    /// proof EMQX would cut off moments later.
    private static let keyRefreshMargin: TimeInterval = 120
    private let session: URLSession
    // Retained for the session's lifetime (URLSession does not strongly hold it).
    private let pinningDelegate = TLSPinningDelegate()

    /// See APIClient's initialiser: injectable so the handshake's request and
    /// response handling can be driven through a `URLProtocol` stub. Production
    /// passes nothing and gets the pinned session.
    init(session: URLSession? = nil) {
        self.session = session
            ?? URLSession(configuration: .default, delegate: pinningDelegate, delegateQueue: nil)
    }

    /// Install a session for tests that need one authenticated already. Not a
    /// production path — nothing else can set `current` without a real handshake.
    func __setSessionForTesting(_ s: Session?) { current = s }

    func currentSession() -> Session? { current }
    func sessionToken() -> String? { current?.sessionToken }
    func mqttToken() -> String? { current?.mqttToken }
    func scope() -> Scope { current?.scope ?? .free }
    func logout() {
        current = nil
        mqttSigner = nil
    }

    // MARK: - Handshake

    /// Sign in, taking the best door this key is entitled to. `secretKey` is the
    /// caller's HQC private key (from IdentityManager/ProfileManager).
    ///
    /// A 402 meant "no live subscription for this key" and fell back to the free
    /// tier. No current server produces one — see the note above on why this
    /// still catches it. A 403 still propagates: the server will not have this
    /// key at all, and retrying the other door would only ask the same
    /// question.
    @discardableResult
    func login(publicKeyHex: String, secretKey: Data) async throws -> Session {
        do {
            return try await handshake(door: .paid, publicKeyHex: publicKeyHex, secretKey: secretKey)
        } catch AuthError.badResponse(let code, _) where code == 402 {
            return try await handshake(door: .free, publicKeyHex: publicKeyHex, secretKey: secretKey)
        }
    }

    private func handshake(door: Door, publicKeyHex: String, secretKey: Data) async throws -> Session {
        let initResp: InitResponse = try await post(path: "\(door.rawValue)/init", body: ["pk": publicKeyHex])
        guard let ct = Data(base64Encoded: initResp.ct) else { throw AuthError.malformedChallenge }

        // Prove key possession: decapsulate → ss → HKDF(ss,"auth). No plaintext is
        // ever returned, so there is no decryption oracle.
        let ss: Data
        do { ss = try HQCService.decapsulate(secretKey: secretKey, ciphertext: ct) }
        catch { throw AuthError.decapsulationFailed }
        let proof = AESService.authProof(ss: ss)

        let signer = Curve25519.Signing.PrivateKey()
        let verify: VerifyResponse = try await post(
            path: "\(door.rawValue)/verify",
            body: ["pk": publicKeyHex, "solution": proof.base64EncodedString(),
                   "mqttSigningKey": signer.publicKey.rawRepresentation.base64EncodedString()]
        )
        // The server echoes both halves of our identity. They have to agree with
        // each other AND with the key we signed in with — a mismatch means we
        // are about to connect to the broker under an id whose ACL rows belong
        // to someone else, which presents as `0x87 NOT AUTHORIZED` on every
        // topic and says nothing about why.
        guard verify.pk.lowercased() == publicKeyHex.lowercased(),
              verify.id.map({ PeerID.matches(publicKeyHex: publicKeyHex, id: $0) }) ?? true else {
            throw AuthError.badResponse(200, "the auth server returned a different identity than the one we signed in with")
        }
        var s = Session(pk: verify.pk, username: verify.username,
                        scope: Scope(rawValue: verify.scope) ?? .free,
                        sessionToken: verify.sessionToken, mqttToken: verify.mqttToken,
                        mqttExpiresAt: verify.mqttExpiresAt)
        s.mqttKeyID = verify.mqttKeyId
        s.mqttKeyExpiresAt = verify.mqttKeyExpiresAt
        current = s
        adoptSigner(signer, keyID: verify.mqttKeyId, serverTime: verify.serverTime)
        return s
    }

    /// Rotate the MQTT connect token — call proactively before `mqttExpiresAt`,
    /// or after EMQX drops the connection on expiry. Authenticated by the cached
    /// REST session bearer, so no KEM handshake is needed.
    @discardableResult
    func refreshMqttToken() async throws -> String {
        guard let s = current else { throw AuthError.notAuthenticated }
        let signer = Curve25519.Signing.PrivateKey()
        let r: RefreshResponse = try await post(
            path: "refresh", bearer: s.sessionToken,
            body: ["mqttSigningKey": signer.publicKey.rawRepresentation.base64EncodedString()])
        current?.mqttToken = r.mqttToken
        current?.mqttExpiresAt = r.mqttExpiresAt
        current?.mqttKeyID = r.mqttKeyId
        current?.mqttKeyExpiresAt = r.mqttKeyExpiresAt
        adoptSigner(signer, keyID: r.mqttKeyId, serverTime: r.serverTime)
        // The server echoes the scope it stored. A refresh rotates a credential;
        // it never re-decides an entitlement, so this only keeps us in step.
        if let scope = Scope(rawValue: r.scope) { current?.scope = scope }
        return r.mqttToken
    }

    /// The password for the next MQTT CONNECT.
    ///
    /// A v1 proof, signed here, when we hold a key with time left on it — the
    /// common case, and it costs no network at all. Otherwise one refresh, which
    /// registers a new key, and then the proof. Against a server that predates
    /// v1 (no key id comes back) this is the rotated bearer token, as before.
    func mqttConnectPassword(clientID: String) async throws -> String {
        if let password = try signedPassword(clientID: clientID) { return password }
        let token = try await refreshMqttToken()
        return try signedPassword(clientID: clientID) ?? token
    }

    /// The broker refused our credentials (CONNACK 4/5). Whatever key we hold
    /// is not one it accepts — revoked, or the table lost it — so the next
    /// connect refreshes instead of signing with it again.
    func invalidateMqttKey() {
        current?.mqttKeyExpiresAt = 0
    }

    private func signedPassword(clientID: String) throws -> String? {
        guard let s = current, let keyID = s.mqttKeyID, let expires = s.mqttKeyExpiresAt,
              let signer = mqttSigner else { return nil }
        let serverNow = Date().timeIntervalSince1970 + clockOffset
        guard expires - serverNow > Self.keyRefreshMargin else { return nil }
        return try MQTTConnectProof.make(clientID: clientID, keyID: keyID, key: signer,
                                         timestamp: Int64(serverNow.rounded()))
    }

    private func adoptSigner(_ signer: Curve25519.Signing.PrivateKey, keyID: String?,
                             serverTime: TimeInterval?) {
        // No key id means the server did not register it (it predates v1), so
        // the key is worthless and is not kept.
        mqttSigner = keyID == nil ? nil : signer
        if let serverTime { clockOffset = serverTime - Date().timeIntervalSince1970 }
    }

    /// Ask the home server where its raw-TCP gateway is and which keys to pin
    /// (`GET /auth/transport`), over this actor's pinned session, and record it
    /// in ServerConfig. Best-effort: any failure leaves the previous answer
    /// (or none), and with none the client simply stays on WSS.
    func refreshTransportDiscovery() async {
        let host = ServerConfig.host
        var req = URLRequest(url: ServerConfig.authBaseURL.appendingPathComponent("transport"))
        req.timeoutInterval = 5
        guard let (data, resp) = try? await session.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        guard let hqn = obj["hqn"] as? [String: Any] else {
            // An explicit null: this server does not advertise a gateway — none
            // exists, or it is switched off (HQN_ENABLED is opt-in). Either way
            // hqn/1 is OFF for this host, compiled-in keys included: the
            // server's "no" is the kill switch. (A request that FAILS changes
            // nothing — that is the network talking, not the server.)
            if obj.keys.contains("hqn") { ServerConfig.setDiscoveredHQN(nil, enabled: false, for: host) }
            return
        }
        ServerConfig.setDiscoveredHQN(HQNEndpoint.parse(hqn), enabled: (hqn["enabled"] as? Bool) ?? false, for: host)
    }

    // MARK: - Networking

    private func post<T: Decodable>(path: String, bearer: String? = nil,
                                    body: [String: String]?) async throws -> T {
        let url = ServerConfig.authBaseURL.appendingPathComponent(path)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let bearer { req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body ?? [:])

        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else {
            throw AuthError.badResponse(code, String(data: data, encoding: .utf8) ?? "")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    // MARK: - Wire types

    private struct InitResponse: Decodable { let ct: String }
    private struct VerifyResponse: Decodable {
        let pk: String
        /// The client id the server computed for `pk`. Checked against our own
        /// derivation rather than adopted — see `handshake`. Optional so a
        /// deployment that has not been updated yet still authenticates.
        let id: String?
        let username: String?
        let scope: String
        let sessionToken: String
        let mqttToken: String
        let mqttExpiresAt: TimeInterval
        // v1 CONNECT proof. Optional: absent from a server that predates it.
        let mqttKeyId: String?
        let mqttKeyExpiresAt: TimeInterval?
        let serverTime: TimeInterval?
    }
    private struct RefreshResponse: Decodable {
        let mqttToken: String
        let scope: String
        let mqttExpiresAt: TimeInterval
        let mqttKeyId: String?
        let mqttKeyExpiresAt: TimeInterval?
        let serverTime: TimeInterval?
    }
}
