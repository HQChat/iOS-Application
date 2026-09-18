import Foundation

/// REST client for the app-api control plane (Phase 1 of the MQTT migration —
/// see deploy/EXTRACTION_PLAN.md). Replaces the WS message types for directory,
/// the friend graph, push-token registration, and account deletion. Every
/// mutating call carries the REST session bearer minted by AuthService; the
/// server resolves it to the caller's pk. Messaging/presence do NOT go here —
/// they ride MQTT (see MQTTService).
actor APIClient {

    enum APIError: LocalizedError {
        case notAuthenticated
        case badResponse(Int, String)
        var errorDescription: String? {
            switch self {
            case .notAuthenticated: return "Not authenticated"
            case .badResponse(let c, let m): return "API error \(c): \(m)"
            }
        }
    }

    /// The directory ships CLIENT IDS — 64 characters per friend, where this
    /// used to be a 14474-character public key on every row of every poll (about
    /// 160 kB a minute for eleven friends). The key is fetched separately, once,
    /// by `peerKey(id:)`.
    struct FriendDTO: Decodable { let id: String; let username: String? }
    /// `username` is optional: the server sends null for an account that has not
    /// claimed a handle, rather than a shared placeholder. That matters because
    /// the client detects a changed identity by finding a different id under the
    /// same display name — two nameless peers sharing "Anonymous" would read as
    /// one of them having re-keyed.
    struct InviteDTO: Decodable { let id: String; let username: String?; let sent_at: Int }

    private let auth: AuthService
    private let session: URLSession
    private let pinningDelegate = TLSPinningDelegate()

    /// `session` is injectable so a test can drive the request/response handling
    /// through a `URLProtocol` stub. Production passes nothing and gets the
    /// pinned session, which is the only configuration that ever ships — the
    /// parameter exists because the alternative is that none of the error
    /// mapping, the bearer header or the URL construction is ever exercised.
    init(auth: AuthService, session: URLSession? = nil) {
        self.auth = auth
        self.session = session
            ?? URLSession(configuration: .default, delegate: pinningDelegate, delegateQueue: nil)
    }

    // MARK: - Directory

    /// Exact-username lookup → client id (nil if unknown). No bulk enumeration
    /// is exposed.
    func lookupUser(username: String) async throws -> String? {
        let item = URLQueryItem(name: "username", value: username)
        var comps = URLComponents(url: ServerConfig.apiBaseURL.appendingPathComponent("users"),
                                  resolvingAgainstBaseURL: false)!
        comps.queryItems = [item]
        struct R: Decodable { let username: String; let id: String? }
        let r: R = try await request("GET", url: comps.url!, auth: false)
        return r.id
    }

    /// The public key a client id names.
    ///
    /// The one place a contact's key enters the app besides an `init` frame. The
    /// CALLER MUST verify it against the id it asked for — `Friend.pin(publicKeyHex:)`
    /// does, and refuses anything else. That check is what makes this route safe
    /// to leave unauthenticated and safe to answer from a server the protocol
    /// does not trust: the id is a commitment to the key, so a substitution is
    /// arithmetic to detect rather than a matter of trusting the response.
    ///
    /// Returns nil when the server does not know that id — a contact whose
    /// account was deleted, which is a real state and not an error.
    func peerKey(id: String) async throws -> String? {
        struct R: Decodable { let id: String; let publicKey: String }
        do {
            let r: R = try await request("GET", path: "peer/\(id)/key", auth: false)
            return r.publicKey
        } catch APIError.badResponse(let code, _) where code == 404 {
            return nil
        }
    }

    /// What this deployment says about itself.
    ///
    /// Unauthenticated, like `/peer/{id}/key`, and for the same kind of reason:
    /// there is nothing here worth withholding, and the one field that matters —
    /// a maintenance notice — has to reach a client that may not be signed in
    /// yet. Returns nil rather than throwing on any failure: a server that does
    /// not answer this is a server with nothing to announce, not an error worth
    /// showing anybody.
    func maintenanceNotice() async -> String? {
        struct Maintenance: Decodable { let active: Bool; let message: String }
        struct R: Decodable { let maintenance: Maintenance? }
        guard let r: R = try? await request("GET", path: "info", auth: false),
              let m = r.maintenance, m.active, !m.message.isEmpty
        else { return nil }
        return m.message
    }

    func setUsername(_ username: String) async throws {
        _ = try await requestVoid("POST", path: "username", body: ["username": username])
    }

    // MARK: - Friend graph

    func getFriends() async throws -> [FriendDTO] {
        struct R: Decodable { let friends: [FriendDTO] }
        let r: R = try await request("GET", path: "friends")
        return r.friends
    }

    func getInvites() async throws -> [InviteDTO] {
        struct R: Decodable { let invites: [InviteDTO] }
        let r: R = try await request("GET", path: "friends/invites")
        return r.invites
    }

    func invite(to identifier: String) async throws {
        _ = try await requestVoid("POST", path: "friends/invite", body: ["to": identifier])
    }

    /// Accept an invite. On success the server grants both members their MQTT
    /// conversation + presence topics, so the client may then subscribe.
    func accept(from identifier: String) async throws {
        _ = try await requestVoid("POST", path: "friends/accept", body: ["from": identifier])
    }

    /// Withdraw an invite we sent, or decline one addressed to us — the server
    /// works out which of the two applies.
    func cancelInvite(peer identifier: String) async throws {
        _ = try await requestVoid("POST", path: "friends/cancel", body: ["peer": identifier])
    }

    func remove(peer identifier: String) async throws {
        _ = try await requestVoid("POST", path: "friends/remove", body: ["peer": identifier])
    }

    // MARK: - Moderation (App Store Guideline 1.2)

    /// Block a contact: unfriend, revoke the topics, and record a row that
    /// survives a re-invite. The server does all three; this is one call.
    func block(peer identifier: String) async throws {
        _ = try await requestVoid("POST", path: "friends/block", body: ["peer": identifier])
    }

    /// Lift a block. Does NOT restore the friendship — the pair re-invite like
    /// strangers, which is what an ordinary unfriend leaves behind too.
    func unblock(peer identifier: String) async throws {
        _ = try await requestVoid("POST", path: "friends/unblock", body: ["peer": identifier])
    }

    /// Who this account has blocked.
    ///
    /// ⚠️ Load-bearing, not informational. A blocked peer is absent from
    /// `/friends` by construction, and `DirectorySync` deletes local rows the
    /// directory stops naming. This list is what tells the two cases apart.
    func getBlocked() async throws -> [String] {
        struct R: Decodable { let blocked: [String] }
        let r: R = try await request("GET", path: "friends/blocked")
        return r.blocked
    }

    /// File a report about one message in a conversation.
    ///
    /// `excerpt` is the reporter's own plaintext copy and is uploaded only
    /// because they chose to upload it — it leaves this device in the clear, and
    /// the server cannot verify it. Both facts are in the UI copy; see
    /// services/server/services/db/migrations/006_reports.sql §0 for exactly what
    /// an attached frame does and does not buy.
    ///
    /// ⚠️ Call this BEFORE `block(peer:)`. The server requires the reporter to be
    /// a member of the conversation, and blocking destroys it.
    func report(conversation hash: String, peer identifier: String, category: String,
                note: String?, excerpt: String?, messageId: String?) async throws -> String {
        struct R: Decodable { let id: String }
        var body: [String: Any] = [
            "conversation": hash, "peer": identifier, "category": category,
        ]
        if let note, !note.isEmpty { body["note"] = note }
        if let excerpt, !excerpt.isEmpty { body["excerpt"] = excerpt }
        if let messageId, !messageId.isEmpty { body["messageId"] = messageId }
        let r: R = try await request("POST", path: "report", body: body)
        return r.id
    }

    // MARK: - Prekeys
    //
    // The ephemeral half of the initial key agreement. The server is untrusted
    // here by design: it can withhold one-time keys to force the weaker
    // medium-term fallback, but it cannot read anything, because the initiator
    // also encapsulates to the peer's PINNED identity key and mixes both secrets
    // into the root.

    /// A peer's claimed bundle: the medium-term key ALWAYS, plus a one-time key
    /// when their pool had one.
    ///
    /// Both, not one or the other — the initial root mixes identity, medium-term
    /// and (when available) one-time, each doing a different job. A null
    /// `oneTime` means the peer's pool was empty, so this session's forward
    /// secrecy runs to their next medium-term rotation rather than ending the
    /// moment they consume the key. A weaker window, not an error.
    struct ClaimedPrekey: Decodable {
        struct OneTime: Decodable { let id: Int; let prekey: String }
        let medium: String
        let oneTime: OneTime?
    }

    /// Publish our bundle: one medium-term key plus a batch of one-time keys.
    /// Additive server-side, so a deeper pool is several calls rather than one
    /// big body — a key costs 14474 hex characters and the body cap is 256 kB.
    func publishPrekeys(medium: String, oneTime: [(id: Int, prekey: String)]) async throws {
        let payload = oneTime.map { ["id": $0.id, "prekey": $0.prekey] as [String: Any] }
        _ = try await requestVoid("POST", path: "prekeys",
                                  body: ["medium": medium, "oneTime": payload])
    }

    /// Claim one prekey for a peer. POST rather than GET with the peer in the
    /// path — kept that way now that an id would fit in a URL, because the
    /// RESPONSE is key material and has no business in an access log or a proxy
    /// cache, and because claiming CONSUMES a one-time key.
    func claimPrekey(peer identifier: String) async throws -> ClaimedPrekey {
        try await request("POST", path: "prekeys/claim", body: ["peer": identifier])
    }

    struct PrekeyCount: Decodable { let remaining: Int; let maxId: Int?; let target: Int }

    /// How many one-time keys we have left, so we know when to replenish.
    func prekeyCount() async throws -> PrekeyCount {
        try await request("GET", path: "prekeys/count")
    }

    // MARK: - Push token / account

    func registerPushToken(platform: String, token: String) async throws {
        _ = try await requestVoid("POST", path: "push/token",
                                  body: ["platform": platform, "token": token])
    }

    func deleteAccount() async throws {
        _ = try await requestVoid("POST", path: "account/delete", body: nil)
    }

    // MARK: - Networking

    /// `body` is `[String: Any]`, not `[String: String]`: a prekey bundle carries
    /// a nested array of `{id, prekey}`. JSONSerialization always accepted that —
    /// the narrower type was the only thing in the way.
    private func makeRequest(_ method: String, url: URL, auth needsAuth: Bool,
                             body: [String: Any]?) async throws -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = method
        if body != nil { req.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if needsAuth {
            guard let token = await auth.sessionToken() else { throw APIError.notAuthenticated }
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body { req.httpBody = try JSONSerialization.data(withJSONObject: body) }
        return req
    }

    private func request<T: Decodable>(_ method: String, path: String? = nil, url: URL? = nil,
                                       auth needsAuth: Bool = true,
                                       body: [String: Any]? = nil) async throws -> T {
        let u = url ?? ServerConfig.apiBaseURL.appendingPathComponent(path ?? "")
        let req = try await makeRequest(method, url: u, auth: needsAuth, body: body)
        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else {
            throw APIError.badResponse(code, String(data: data, encoding: .utf8) ?? "")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    @discardableResult
    private func requestVoid(_ method: String, path: String,
                             body: [String: Any]?) async throws -> Bool {
        struct OK: Decodable { let ok: Bool? }
        let _: OK = try await request(method, path: path, body: body)
        return true
    }
}
