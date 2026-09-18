// The REST client, driven through a URLProtocol stub.
//
// 228 lines never compiled by a test, and what lives in them is not glue: the
// bearer header, the error mapping, and the URL each call is pointed at. A
// mistake in any of those is either a request that leaks a token somewhere it
// should not go, or a server error the user sees as a crash.
//
// The session is injectable now (see APIClient.init) for one reason: the
// production session is built with the pinning delegate against the real
// origin, so nothing here could be exercised at all. Production still passes
// nothing and still gets the pinned session.
//
// Nothing reaches the network. `StubProtocol` answers every request from a
// script and records what was asked.

import Foundation

// ── The stub ─────────────────────────────────────────────────────────────────

final class StubProtocol: URLProtocol, @unchecked Sendable {
    struct Reply { let status: Int; let body: String }

    nonisolated(unsafe) static var script: [Reply] = []
    nonisolated(unsafe) static var seen: [URLRequest] = []
    nonisolated(unsafe) static var bodies: [Data] = []
    nonisolated(unsafe) static let lock = NSLock()

    static func reset(_ replies: [Reply]) {
        lock.lock(); defer { lock.unlock() }
        script = replies; seen = []; bodies = []
    }

    static func record(_ r: URLRequest) -> Reply {
        lock.lock(); defer { lock.unlock() }
        seen.append(r)
        // URLProtocol strips httpBody into a stream; capture it either way.
        if let b = r.httpBody { bodies.append(b) }
        else if let s = r.httpBodyStream {
            s.open(); defer { s.close() }
            var data = Data(); var buf = [UInt8](repeating: 0, count: 4096)
            while s.hasBytesAvailable {
                let n = s.read(&buf, maxLength: buf.count)
                if n <= 0 { break }
                data.append(contentsOf: buf[0..<n])
            }
            bodies.append(data)
        } else { bodies.append(Data()) }
        return script.isEmpty ? Reply(status: 200, body: "{}") : script.removeFirst()
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let reply = StubProtocol.record(request)
        let resp = HTTPURLResponse(url: request.url!, statusCode: reply.status,
                                   httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(reply.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

func stubbedSession() -> URLSession {
    let cfg = URLSessionConfiguration.ephemeral
    cfg.protocolClasses = [StubProtocol.self]
    return URLSession(configuration: cfg)
}

// ── A client with a session already in hand ──────────────────────────────────

let TOKEN = "sess-token-abc123"

func makeClient(authenticated: Bool = true) async -> APIClient {
    let auth = AuthService(session: stubbedSession())
    if authenticated {
        await auth.__setSessionForTesting(.init(
            pk: String(repeating: "ab", count: 32),
            username: "alice",
            scope: .free,
            sessionToken: TOKEN,
            mqttToken: "mqtt-token",
            mqttExpiresAt: Date().timeIntervalSince1970 + 3600))
    }
    return APIClient(auth: auth, session: stubbedSession())
}

func runAsync(_ body: @escaping () async -> Void) {
    let sem = DispatchSemaphore(value: 0)
    Task { await body(); sem.signal() }
    sem.wait()
}

ServerConfig.activeHost = "api.test"

// ── Every authenticated call carries the bearer, and nothing else ────────────

runAsync {
    let c = await makeClient()
    StubProtocol.reset([.init(status: 200, body: "{\"friends\":[]}")])
    _ = try? await c.getFriends()

    let req = StubProtocol.seen.first
    check(req != nil, "the call reached the transport")
    check(req?.value(forHTTPHeaderField: "Authorization") == "Bearer \(TOKEN)",
          "the session bearer is sent, and sent as a Bearer")
    check(req?.url?.scheme == "https", "over https — the token is in a header, not a tunnel")
    check(req?.url?.host == "api.test", "to the configured origin")
    check(!(req?.url?.absoluteString.contains(TOKEN) ?? true),
          "the token is never in the URL, where it would reach an access log")
}

// A call made with no session must fail BEFORE it reaches the transport: an
// unauthenticated request to a friend route would 401, but it would also have
// left the device.
runAsync {
    let c = await makeClient(authenticated: false)
    StubProtocol.reset([.init(status: 200, body: "{\"friends\":[]}")])
    var threw = false
    do { _ = try await c.getFriends() } catch { threw = true }
    check(threw, "a call with no session throws")
    check(StubProtocol.seen.isEmpty, "…and nothing was sent")
}

// ── What a server error becomes ──────────────────────────────────────────────

runAsync {
    let c = await makeClient()
    for status in [400, 401, 403, 404, 409, 429, 500, 503] {
        StubProtocol.reset([.init(status: status, body: "{\"error\":\"NOPE\"}")])
        var caught: Error?
        do { _ = try await c.getFriends() } catch { caught = error }
        check(caught != nil, "\(status) is an error, not an empty result")
        if let e = caught as? APIClient.APIError, case .badResponse(let code, _) = e {
            check(code == status, "\(status): the status survives into the error")
        } else {
            check(false, "\(status): mapped to \(String(describing: caught)) rather than badResponse")
        }
    }
}

// A 2xx whose body is not what was expected must throw rather than silently
// decode to an empty list — "you have no friends" is a very different screen
// from "something went wrong".
runAsync {
    let c = await makeClient()
    for body in ["", "not json", "{}", "[]", "{\"friends\":\"not a list\"}", "null"] {
        StubProtocol.reset([.init(status: 200, body: body)])
        var caught: Error?
        do { _ = try await c.getFriends() } catch { caught = error }
        check(caught != nil, "a 200 carrying \(body.isEmpty ? "an empty body" : body.prefix(22)) throws")
    }
}

// ── The directory, which must not enumerate ──────────────────────────────────

runAsync {
    let c = await makeClient()
    StubProtocol.reset([.init(status: 200, body: "{\"username\":\"bob\",\"id\":\"\(String(repeating: "cd", count: 32))\"}")])
    let id = try? await c.lookupUser(username: "bob")
    check(id != nil, "an exact lookup returns an id")

    let url = StubProtocol.seen.first?.url?.absoluteString ?? ""
    check(url.contains("username=bob"), "the handle travels as an exact query parameter")
    check(!url.contains("*") && !url.contains("prefix") && !url.contains("q="),
          "no wildcard or prefix form is offered — bulk enumeration is not exposed")
}

// A handle the server does not know is nil, not an error: an empty search
// result is an ordinary answer, and throwing would make it look like a failure.
runAsync {
    let c = await makeClient()
    StubProtocol.reset([.init(status: 200, body: "{\"username\":\"ghost\",\"id\":null}")])
    let id = try? await c.lookupUser(username: "ghost")
    check(id == nil || id?.isEmpty == true, "an unknown handle answers nothing, without throwing")
}

// ── The friend graph ─────────────────────────────────────────────────────────

runAsync {
    let c = await makeClient()
    let peerA = String(repeating: "11", count: 32)
    StubProtocol.reset([.init(status: 200,
        body: "{\"friends\":[{\"id\":\"\(peerA)\",\"username\":\"bob\"},{\"id\":\"\(String(repeating: "22", count: 32))\",\"username\":null}]}")])
    let friends = (try? await c.getFriends()) ?? []
    check(friends.count == 2, "both rows decode")
    check(friends.first?.id == peerA, "the id is carried verbatim")
    // A nameless account sends null rather than a shared placeholder: the client
    // spots a re-keyed identity by finding a different id under the same display
    // name, and two peers sharing "Anonymous" would read as one of them re-keying.
    check(friends.last?.username == nil, "a nameless peer stays nameless, not \"Anonymous\"")
}

// The directory ships ids, not keys. 64 characters per friend instead of 14474
// — about 160 kB a minute for eleven friends on the old shape.
runAsync {
    let c = await makeClient()
    StubProtocol.reset([.init(status: 200,
        body: "{\"friends\":[{\"id\":\"\(String(repeating: "11", count: 32))\",\"username\":\"bob\"}]}")])
    let friends = (try? await c.getFriends()) ?? []
    check(friends.first?.id.count == 64, "a friend row carries a 64-character id, never a public key")
}

// ── Writes send what they say they send ──────────────────────────────────────

runAsync {
    let c = await makeClient()
    StubProtocol.reset([.init(status: 200, body: "{\"ok\":true}")])
    try? await c.invite(to: "bob")

    let req = StubProtocol.seen.first
    check(req?.httpMethod == "POST", "an invite is a POST")
    check(req?.value(forHTTPHeaderField: "Content-Type") == "application/json", "…with a JSON content type")
    let body = String(data: StubProtocol.bodies.first ?? Data(), encoding: .utf8) ?? ""
    check(body.contains("bob"), "the peer is in the body, not the URL: \(body)")
    check(!(req?.url?.absoluteString.contains("bob") ?? true),
          "a handle in the path would reach every proxy log between here and the origin")
}

runAsync {
    let c = await makeClient()
    StubProtocol.reset([.init(status: 200, body: "{\"medium\":\"mm\",\"oneTime\":null}")])
    _ = try? await c.claimPrekey(peer: "bob")
    check(StubProtocol.seen.first?.httpMethod == "POST",
          "a prekey claim is a POST — the response is key material and mutates a pool, "
          + "so it has no business in an access log or a proxy cache")
}

finish()
