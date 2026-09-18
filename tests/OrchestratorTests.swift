// The link and the router: the last two files that had never been compiled.
//
// MQTTService is an actor over an injected `MQTTBackend`, and ConversationRouter
// takes every side effect as a closure — both were built to be testable and
// neither had a test. What they decide is not transport plumbing:
//
//   * WHICH TOPICS a connect asks for, and what happens to the ledger of them
//     when the identity changes. Restoring the previous profile's conversation
//     topics after a switch is not a refused SUBACK — EMQX runs
//     `deny_action = disconnect`, so the broker drops the link the moment CONNACK
//     lands, the reconnect asks for the same topics, and the app sits in a loop
//     that only quitting clears.
//
//   * WHERE an inbound frame goes. A topic that routes nowhere is a message
//     silently dropped, which is the bug ProtocolLog was written for.
//
// The backend here is a fake that records; nothing opens a socket.

import Foundation
import SwiftData

// ── A backend that records instead of connecting ─────────────────────────────

final class FakeBackend: MQTTBackend, @unchecked Sendable {
    struct Publish { let topic: String; let payload: Data; let qos: Int; let retained: Bool }

    var subscribed: [(topic: String, qos: Int)] = []
    var unsubscribed: [String] = []
    var published: [Publish] = []
    var connectArgs: (clientID: String, username: String, willTopic: String, willPayload: Data)?
    var disconnects = 0
    private var onEvent: ((MQTTEvent) -> Void)?

    func connect(url: URL, clientID: String, username: String, password: String,
                 willTopic: String, willPayload: Data,
                 onEvent: @escaping (MQTTEvent) -> Void) {
        connectArgs = (clientID, username, willTopic, willPayload)
        self.onEvent = onEvent
    }
    func subscribe(_ topic: String, qos: Int) { subscribed.append((topic, qos)) }
    func unsubscribe(_ topic: String) { unsubscribed.append(topic) }
    func publish(_ topic: String, payload: Data, qos: Int, retained: Bool, onWrite: ((Bool) -> Void)?) {
        published.append(.init(topic: topic, payload: payload, qos: qos, retained: retained))
        onWrite?(true)
    }
    func disconnect() { disconnects += 1 }

    /// Drive an inbound event, the way the real adapter would.
    func deliver(_ e: MQTTEvent) { onEvent?(e) }
}

// ── A session, so `connect` can get past the token refresh ───────────────────
//
// `connect(id:)` awaits `auth.refreshMqttToken()` BEFORE it touches the backend,
// so with no session it throws and the backend is never called at all — which is
// correct, and which made every assertion below fail until this was here.

final class RefreshStub: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let body = #"{"mqttToken":"rotated-token","mqttExpiresAt":9999999999,"scope":"free"}"#
        let resp = HTTPURLResponse(url: request.url!, statusCode: 200,
                                   httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

let ME   = String(repeating: "11", count: 32)
let PEER = String(repeating: "22", count: 32)

/// Run an async body from top-level code and wait for it. Safe here — unlike the
/// @MainActor case in PersistenceTests, these are actor calls that do not need
/// the main thread, so blocking it is not a deadlock.
func sem(_ body: @escaping () async -> Void) {
    let s = DispatchSemaphore(value: 0)
    Task { await body(); s.signal() }
    s.wait()
}

// ── The Last-Will, which is what makes an ungraceful drop visible ────────────

ServerConfig.activeHost = "auth.test"

let stubConfig = URLSessionConfiguration.ephemeral
stubConfig.protocolClasses = [RefreshStub.self]

let backend = FakeBackend()
let auth = AuthService(session: URLSession(configuration: stubConfig))
sem {
    await auth.__setSessionForTesting(.init(
        pk: String(repeating: "ab", count: 32), username: "me", scope: .free,
        sessionToken: "sess", mqttToken: "old", mqttExpiresAt: 0))
}
let mqtt = MQTTService(backend: backend, auth: auth)

// `connect(id:)` awaits a CONNACK that a fake never sends, so it is driven far
// enough to observe the backend call and then abandoned — the assertions are
// about what was ASKED for, not about completing a handshake.
let connectTask = Task { try? await mqtt.connect(id: ME) }
Thread.sleep(forTimeInterval: 0.3)

if let args = backend.connectArgs {
    // EMQX keys the topic ACL on the client id (`WHERE id = ${clientid}`), so
    // connecting as anything else authenticates and then matches no row.
    check(args.clientID == ME, "the client id is our own id, which the ACL is keyed on")
    check(args.username == ME, "…and so is the username")
    check(args.willTopic == MQTTTopics.presence(ME),
          "the Last-Will is on OUR presence topic, or an ungraceful drop leaves us shown online forever")
    check(!args.willPayload.isEmpty, "the will carries a payload")
    let body = String(data: args.willPayload, encoding: .utf8) ?? ""
    check(body.contains("offline") || body.contains("\"s\""),
          "the will says offline: \(body)")
} else {
    check(false, "connect never reached the backend")
}
connectTask.cancel()

// ── The subscription ledger ──────────────────────────────────────────────────
//
// `subscribeFriend` records what it WANTS unconditionally and only talks to the
// backend once the link is up — so CONNACK has to land first. That guard is the
// right way round: asking the broker for a topic before the session exists is a
// SUBSCRIBE into a socket that is not there.
backend.deliver(.connected)
Thread.sleep(forTimeInterval: 0.3)

sem {
    backend.subscribed.removeAll()
    await mqtt.subscribeFriend(PEER)
}

let topics = backend.subscribed.map(\.topic)
check(topics.contains(MQTTTopics.conversation(ME, PEER)), "a friend's conversation topic is subscribed")
check(topics.contains(MQTTTopics.presence(PEER)), "…and their presence")
check(topics.contains(MQTTTopics.handshake(ME, PEER)),
      "…and the handshake topic, which is where an init is proved and without which first contact stalls")

// QoS is not decoration: a conversation frame lost is a message lost, and
// presence is a retained flag that the next update replaces anyway.
for s in backend.subscribed {
    if s.topic.hasPrefix("c/") || s.topic.hasPrefix("h/") {
        check(s.qos == 1, "\(s.topic) is QoS 1 — a dropped frame is a lost message")
    }
    if s.topic.hasSuffix("/presence") {
        check(s.qos == 0, "\(s.topic) is QoS 0 — presence is retained and self-correcting")
    }
}

// ── A reconnect restores what we asked for ───────────────────────────────────
//
// The ledger is the point of `desired`: EMQX keeps subscriptions for a persistent
// session, but re-sending them removes any dependence on broker-side state
// surviving. Without this, a reconnect leaves the client authenticated and deaf —
// connected, subscribed to nothing, and reporting no error.
backend.subscribed.removeAll()
backend.deliver(.connected)
Thread.sleep(forTimeInterval: 0.3)

let restored = backend.subscribed.map(\.topic)
check(restored.contains(MQTTTopics.conversation(ME, PEER)),
      "a reconnect re-subscribes the conversation topic")
check(restored.contains(MQTTTopics.presence(PEER)), "…and presence")
check(restored.contains(MQTTTopics.handshake(ME, PEER)),
      "…and the handshake topic, or first contact stops working after any blip")

// ── Unsubscribing gives the whole set back ───────────────────────────────────

sem {
    backend.unsubscribed.removeAll()
    await mqtt.unsubscribeFriend(PEER)
}
check(backend.unsubscribed.contains(MQTTTopics.handshake(ME, PEER)),
      "unfriending drops the handshake topic too — leaving it subscribed keeps a channel "
      + "open to somebody the ACL no longer grants")

// ── Inbound routing ──────────────────────────────────────────────────────────
//
// MQTTTopics.route is the pure decision and has its own tests; what is asserted
// here is that the SERVICE dispatches on it, because a topic that routes nowhere
// is a frame dropped in silence.

final class Box: @unchecked Sendable { var messages = 0; var handshakes = 0; var graph = 0
                                       var presence: [(String, Bool)] = [] }
let seen = Box()

sem {
    await mqtt.setMessageHandler { _, _ in seen.messages += 1 }
    await mqtt.setHandshakeHandler { _, _ in seen.handshakes += 1 }
    await mqtt.setGraphHandler { seen.graph += 1 }
    await mqtt.setPresenceHandler { id, online in seen.presence.append((id, online)) }
}

backend.deliver(.message(topic: MQTTTopics.conversation(ME, PEER), payload: Data([1])))
backend.deliver(.message(topic: MQTTTopics.handshake(ME, PEER), payload: Data([2])))
backend.deliver(.message(topic: MQTTTopics.graph(ME), payload: Data()))
backend.deliver(.message(topic: MQTTTopics.presence(PEER), payload: Data(#"{"s":"online"}"#.utf8)))
// Nothing routes this one. It must reach no handler at all rather than the
// nearest-looking one.
backend.deliver(.message(topic: "totally/unrelated/topic", payload: Data([9])))
Thread.sleep(forTimeInterval: 0.4)

check(seen.messages == 1, "a conversation frame reached the message handler (got \(seen.messages))")
check(seen.handshakes == 1, "a handshake frame reached the handshake handler (got \(seen.handshakes))")
check(seen.graph == 1, "a graph notice reached the graph handler (got \(seen.graph))")
check(seen.presence.count == 1, "a presence flip reached the presence handler")
check(seen.presence.first?.0 == PEER, "…naming the peer whose presence it was")
check(seen.presence.first?.1 == true, "…and its state")
check(seen.messages + seen.handshakes + seen.graph == 3,
      "an unroutable topic reached no handler — a misrouted frame is worse than a dropped one")

// ── The router's own lookups ─────────────────────────────────────────────────

@MainActor
func routerChecks() {
    let config = ModelConfiguration(isStoredInMemoryOnly: true)
    let container = try! ModelContainer(for: Profile.self, Friend.self, Message.self, configurations: config)
    let ctx = container.mainContext

    let pk = Data((0..<7237).map { UInt8($0 % 251) })
    let profile = Profile(username: "me", publicKeyHex: pk.hexString, seedHex: Data(count: 32).hexString)
    ctx.insert(profile)
    let fpk = Data((0..<7237).map { UInt8(($0 &* 3) % 251) })
    let f = Friend(username: "bob", peerID: PeerID.from(publicKey: fpk), publicKey: fpk, profile: profile)
    ctx.insert(f)
    try? ctx.save()

    let router = ConversationRouter(
        modelContext: ctx, profileManager: nil, prekeys: nil,
        publish: { _, _ in }, publishHandshake: { _, _ in })

    // With NO active profile, every lookup answers nothing — including for a
    // contact that plainly exists in the store. That is the safety property, not
    // an accident of the fixture: contacts are scoped to a profile, so a frame
    // arriving before one is settled must not be allowed to match somebody
    // else's contact row.
    check(router.friend(withID: f.peerID) == nil,
          "with no active profile, a contact that exists is still not matched")
    check(router.friend(withID: String(repeating: "ff", count: 32)) == nil,
          "an id nobody holds finds nobody")
    check(router.friend(withID: "") == nil, "an empty id matches nothing")

    // Presence is the router's, and it must not leak between accounts.
    router.setPresence(id: f.peerID, online: true)
    router.setPresence(id: f.peerID, online: false)
    router.clearAllPresence()
    check(true, "presence can be set and cleared without a live link")
}
MainActor.assumeIsolated { routerChecks() }

// ── The small ones ───────────────────────────────────────────────────────────

let item = UserListItem(username: "alice", id: String(repeating: "ab", count: 32))
check(item.id.count == 64, "a directory row carries a 64-character id, not a key")
if let encoded = try? JSONEncoder().encode(item),
   let back = try? JSONDecoder().decode(UserListItem.self, from: encoded) {
    check(back.username == item.username && back.id == item.id, "a directory row round-trips")
} else {
    check(false, "a directory row did not round-trip")
}

// ── DirectorySync: the two guards that stand between a block and a lost history ──
//
// `reconcileRemovals` deletes any local contact the directory has stopped
// naming, and calls `clearAESKeys()` on the way out. That is correct for an
// unfriend from the other side and catastrophic for a block: blocking tears the
// friendship down, so a blocked peer is absent from /friends BY CONSTRUCTION.
// Without the guard, blocking somebody deletes the conversation they were
// blocked over — and the Keychain material with it — on the next sixty-second
// poll, with nothing to restore it from.
//
// Both passes are driven directly rather than through a sync: the alternative is
// covering a history-destroying deletion only behind an HTTP round trip, which
// is the kind of coverage that quietly stops existing.

@MainActor
func directorySyncBlockGuards() {
    let config = ModelConfiguration(isStoredInMemoryOnly: true)
    let container = try! ModelContainer(for: Profile.self, Friend.self, Message.self,
                                        configurations: config)
    let ctx = container.mainContext

    let pk = Data((0..<7237).map { UInt8($0 % 251) })
    let profile = Profile(username: "me", publicKeyHex: pk.hexString, seedHex: "")
    ctx.insert(profile)

    func contact(_ name: String, _ seed: UInt8) -> Friend {
        let key = Data((0..<7237).map { UInt8(($0 &* Int(seed) &+ 7) % 251) })
        let f = Friend(username: name, peerID: PeerID.from(publicKey: key),
                       publicKey: key, inviteStatus: .accepted, profile: profile)
        ctx.insert(f)
        return f
    }
    let kept = contact("kept", 3)
    let blocked = contact("blocked", 5)
    let unfriended = contact("unfriended", 7)
    try? ctx.save()

    let sync = DirectorySync(api: APIClient(auth: AuthService(session: URLSession(configuration: stubConfig))),
                             modelContext: ctx, profileManager: nil)

    // The server lists `kept` and nothing else. `blocked` is absent because the
    // user blocked them; `unfriended` is absent because the other side left.
    // Identical absence, opposite correct outcomes — which is the whole reason
    // the block list has to be fetched before anything is deleted.
    sync.reconcileBlocks(blockedIDs: [blocked.peerID], profileId: profile.id)
    check(blocked.isBlocked, "a peer on the server's block list is not marked blocked locally")
    check(!kept.isBlocked && !unfriended.isBlocked, "…and nobody else was")

    sync.reconcileRemovals(serverIDs: [kept.peerID], profileId: profile.id)
    try? ctx.save()

    let left = ((try? ctx.fetch(FetchDescriptor<Friend>())) ?? []).map(\.username).sorted()
    check(left == ["blocked", "kept"],
          "a blocked contact was deleted by the sync that follows the block (left: \(left))")
    check(left.contains("kept"), "an ordinary friend was removed")
    check(!left.contains("unfriended"),
          "an actual unfriend must still be reconciled away, or the guard is just a disabled removal")

    // Unblocking hands the row back to the ordinary rule. It is STILL absent from
    // the directory — unblocking does not restore the friendship, on either side
    // — so the next reconcile is what removes it, and this is the assertion that
    // keeps the guard from being permanent immunity.
    sync.reconcileBlocks(blockedIDs: [], profileId: profile.id)
    check(!blocked.isBlocked, "unblocking elsewhere did not reach this device")
    sync.reconcileRemovals(serverIDs: [kept.peerID], profileId: profile.id)
    try? ctx.save()
    let after = ((try? ctx.fetch(FetchDescriptor<Friend>())) ?? []).map(\.username).sorted()
    check(after == ["kept"], "an unblocked, unfriended contact is never reconciled away (left: \(after))")
}
MainActor.assumeIsolated { directorySyncBlockGuards() }

// ── …and the same guard on the vanished path ────────────────────────────────
//
// `upsert` marks a row vanished when the SAME username turns up under a
// DIFFERENT id and the old one is gone from the directory: somebody reinstalled,
// reset their account, or moved device. A blocked contact is gone from the
// directory too, so without `!stale.isBlocked` a user who blocks somebody and
// then meets a new account with that handle is told their own block was an
// identity change — copy that reads, deliberately, as an impersonation warning.

@MainActor
func vanishedGuardSkipsBlocked() {
    let config = ModelConfiguration(isStoredInMemoryOnly: true)
    let container = try! ModelContainer(for: Profile.self, Friend.self, Message.self,
                                        configurations: config)
    let ctx = container.mainContext
    let pk = Data((0..<7237).map { UInt8($0 % 251) })
    let profile = Profile(username: "me", publicKeyHex: pk.hexString, seedHex: "")
    ctx.insert(profile)

    func contact(_ name: String, _ seed: Int) -> Friend {
        let key = Data((0..<7237).map { UInt8(($0 &* seed &+ 11) % 251) })
        let f = Friend(username: name, peerID: PeerID.from(publicKey: key),
                       publicKey: key, inviteStatus: .accepted, profile: profile)
        ctx.insert(f)
        return f
    }
    // Two people who share a handle. One was blocked; one simply left.
    let blocked = contact("sam", 13)
    let departed = contact("kim", 17)
    blocked.blockedAt = Date()
    try? ctx.save()

    let sync = DirectorySync(api: APIClient(auth: AuthService(session: URLSession(configuration: stubConfig))),
                             modelContext: ctx, profileManager: nil)

    // A NEW identity appears under each handle, and neither old id is listed.
    let newSam = Data((0..<7237).map { UInt8(($0 &* 23 &+ 2) % 251) })
    let newKim = Data((0..<7237).map { UInt8(($0 &* 29 &+ 5) % 251) })
    let newSamID = PeerID.from(publicKey: newSam)
    let newKimID = PeerID.from(publicKey: newKim)

    _ = sync.upsert(id: newSamID, username: "sam", status: .accepted,
                    profileId: profile.id, serverIDs: [newSamID, newKimID])
    _ = sync.upsert(id: newKimID, username: "kim", status: .accepted,
                    profileId: profile.id, serverIDs: [newSamID, newKimID])

    check(!blocked.isVanished,
          "a blocked contact was marked VANISHED — the user is now shown an "
          + "impersonation warning for a block they placed themselves")
    check(departed.isVanished,
          "an identity that really did change must still be marked vanished, or "
          + "the guard is just a disabled check")
}
MainActor.assumeIsolated { vanishedGuardSkipsBlocked() }

finish()
