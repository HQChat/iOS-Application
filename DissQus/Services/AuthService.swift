import Foundation

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
/// The `sessionToken` is a multi-use REST bearer (APIClient + refresh); the
/// `mqttToken` is the MQTT CONNECT password — valid ~5m and reusable across
/// reconnects. EMQX force-disconnects at `mqttExpiresAt`, then the client calls
/// refreshMqttToken() and reconnects (expiration-based rotation).
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
    func logout() { current = nil }

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

        let verify: VerifyResponse = try await post(
            path: "\(door.rawValue)/verify",
            body: ["pk": publicKeyHex, "solution": proof.base64EncodedString()]
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
        let s = Session(pk: verify.pk, username: verify.username,
                        scope: Scope(rawValue: verify.scope) ?? .free,
                        sessionToken: verify.sessionToken, mqttToken: verify.mqttToken,
                        mqttExpiresAt: verify.mqttExpiresAt)
        current = s
        return s
    }

    /// Rotate the MQTT connect token — call proactively before `mqttExpiresAt`,
    /// or after EMQX drops the connection on expiry. Authenticated by the cached
    /// REST session bearer, so no KEM handshake is needed.
    @discardableResult
    func refreshMqttToken() async throws -> String {
        guard let s = current else { throw AuthError.notAuthenticated }
        let r: RefreshResponse = try await post(path: "refresh", bearer: s.sessionToken, body: nil)
        current?.mqttToken = r.mqttToken
        current?.mqttExpiresAt = r.mqttExpiresAt
        // The server echoes the scope it stored. A refresh rotates a credential;
        // it never re-decides an entitlement, so this only keeps us in step.
        if let scope = Scope(rawValue: r.scope) { current?.scope = scope }
        return r.mqttToken
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
    }
    private struct RefreshResponse: Decodable {
        let mqttToken: String
        let scope: String
        let mqttExpiresAt: TimeInterval
    }
}
