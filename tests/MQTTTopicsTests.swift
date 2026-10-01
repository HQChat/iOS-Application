// Inbound topic routing.
//
// This exists because the routing decision was an if/else chain with an
// implicit "otherwise do nothing", and the thing it silently did nothing with
// was every frame delivered to this client's own inbox — where `init` frames go
// and nowhere else. The bot opened sessions, claimed one-time prekeys, sealed
// greetings and published them; the client received them and dropped them on
// the floor; the conversation read "not encrypted" forever and no log anywhere
// said why.
//
// So the interesting assertions are not that a good topic routes. They are that
// EVERY topic the broker can deliver to us routes somewhere, and that the
// something is never silence.

import Foundation

let ID_A = String(repeating: "a", count: 64)
let ID_B = String(repeating: "b", count: 64)

/// A friendship's topics as the server would hand them out: two random ids.
func topics(_ convo: Character, _ shake: Character) -> FriendTopics {
    FriendTopics(convoID: String(repeating: convo, count: 64),
                 handshakeID: String(repeating: shake, count: 64))!
}
let AB = topics("1", "2")
let AC = topics("3", "4")

func expect(_ actual: InboundRoute, _ expected: InboundRoute, _ what: String) {
    guard actual == expected else {
        print("❌ \(what): expected \(expected), got \(actual)")
        exit(1)
    }
    print("✓ \(what)")
}

func expectUnroutable(_ topic: String, _ what: String) {
    if case .unroutable = MQTTTopics.route(topic) { print("✓ \(what)"); return }
    print("❌ \(what): expected unroutable, got \(MQTTTopics.route(topic))")
    exit(1)
}

print("── inbound topic routing ──────────────────────")

// THE REGRESSION. Our own inbox is subscribed on every connect, and it is the
// only topic an `init` is ever published to.
expect(MQTTTopics.route(MQTTTopics.inbox(ID_A)), .inbox,
       "our own inbox routes to the message handler")
expect(MQTTTopics.route("u/\(ID_B)/inbox"), .inbox,
       "any well-formed inbox topic routes — the id in it is the OWNER, not the sender")

expect(MQTTTopics.route(MQTTTopics.graph(ID_A)), .graph,
       "our graph topic routes — the server's push that the friend graph moved")

expect(MQTTTopics.route(MQTTTopics.presence(ID_A)), .presence(peerID: ID_A),
       "presence routes and carries the peer id")
expect(MQTTTopics.route(AB.conversation), .conversation,
       "a conversation topic routes")
expect(MQTTTopics.route(AB.handshake), .handshake,
       "a handshake topic routes")

// The topics are the server's ids, verbatim, under their own prefixes.
guard AB.conversation == "cv/" + String(repeating: "1", count: 64),
      AB.handshake == "hs/" + String(repeating: "2", count: 64) else {
    print("❌ topics are cv/{convo_id} and hs/{handshake_id}"); exit(1)
}
print("✓ the topics are cv/{convo_id} and hs/{handshake_id}")

// Only the shape the server mints. Anything else — a server that predates the
// ids, a truncated or uppercase value, a slash smuggled into a topic string —
// yields no topics at all rather than a topic built from it.
for (convo, shake, what) in [
    (nil, String(repeating: "2", count: 64), "a missing conversation id"),
    (String(repeating: "1", count: 64), nil, "a missing handshake id"),
    (String(repeating: "1", count: 63), String(repeating: "2", count: 64), "a short id"),
    (String(repeating: "A", count: 64), String(repeating: "2", count: 64), "an uppercase id"),
    (String(repeating: "1", count: 62) + "/#", String(repeating: "2", count: 64), "an id carrying a wildcard"),
] as [(String?, String?, String)] {
    guard FriendTopics(convoID: convo, handshakeID: shake) == nil else {
        print("❌ \(what) was accepted as a topic id"); exit(1)
    }
    print("✓ \(what) yields no topics")
}

// The old derivable topics are gone: nothing routes them as a conversation.
expectUnroutable("c/" + String(repeating: "1", count: 64), "a retired c/ topic")
expectUnroutable("h/" + String(repeating: "1", count: 64), "a retired h/ topic")

// Shape checks: a middle segment that is not a client id names nobody, and
// treating it as a peer would show a contact that never comes online.
expectUnroutable("u/not-an-id/presence", "a malformed id in a presence topic")
expectUnroutable("u/\(ID_A)/typing", "an unknown topic kind under u/")

// The three `u/` kinds must stay distinct. Collapsing graph into presence would
// resync the directory on every online/offline flip; collapsing it into inbox
// would hand a payload with no envelope to the message handler.
guard MQTTTopics.route(MQTTTopics.graph(ID_A)) != MQTTTopics.route(MQTTTopics.inbox(ID_A)),
      MQTTTopics.route(MQTTTopics.graph(ID_A)) != MQTTTopics.route(MQTTTopics.presence(ID_A)) else {
    print("❌ graph, inbox and presence must route differently"); exit(1)
}
print("✓ graph, inbox and presence are three different routes")
expectUnroutable("u/\(ID_A)", "a truncated u/ topic")
expectUnroutable("", "the empty topic")
expectUnroutable("cv/", "a conversation topic with no id")
expectUnroutable("hs/", "a handshake topic with no id")
expectUnroutable("nonsense", "an unprefixed topic")

// An uppercase id is NOT the same identity — ids are lowercase hex by
// definition, and accepting a case variant would split one peer into two.
expectUnroutable("u/\(String(repeating: "A", count: 64))/presence",
                 "an uppercase id is not a client id")

print("")
print("── subscription ledger ────────────────────────")
// A subscription is re-offered on every connect. A topic the broker REFUSES
// is forgotten, not retried. Under the old deny_action = disconnect a refusal
// also dropped the link, so a topic left in the wanted set dropped every
// connection after it — the "A adds B and B's app loops forever" report. The
// broker only refuses the packet now, but re-offering a refused topic is still
// pointless: the next directory sync re-asks with the topics the server holds.

var ledger = SubscriptionLedger()
ledger.want(AB.conversation, qos: 1)
ledger.want("u/\(ID_A)/presence", qos: 0)
guard ledger.toSubscribe.count == 2 else { print("❌ two wanted topics"); exit(1) }
print("✓ wanted topics are offered on connect")

guard ledger.toSubscribe.first?.qos == 1 else { print("❌ qos is preserved"); exit(1) }
print("✓ …at the qos they were asked for")

ledger.refused(AB.conversation)
guard !ledger.toSubscribe.contains(where: { $0.topic == AB.conversation }) else {
    print("❌ a refused topic must not be re-offered"); exit(1)
}
print("✓ a refused topic is NOT re-offered on the next connect")

guard ledger.toSubscribe.count == 1 else { print("❌ other topics survive a refusal"); exit(1) }
print("✓ …and a refusal does not disturb the topics that were granted")

// Once a sync names it again, asking again works.
ledger.want(AB.conversation, qos: 1)
guard ledger.toSubscribe.contains(where: { $0.topic == AB.conversation }) else {
    print("❌ a refused topic can be asked for again"); exit(1)
}
print("✓ a refused topic can be asked for again")

ledger.forget(AB.conversation)
guard !ledger.toSubscribe.contains(where: { $0.topic == AB.conversation }) else {
    print("❌ unfriending forgets the topic"); exit(1)
}
print("✓ unfriending forgets the topic")

ledger.removeAll()
guard ledger.toSubscribe.isEmpty else { print("❌ a profile switch carries nothing over"); exit(1) }
print("✓ a profile switch carries nothing over")

// ── Topic ↔ sender binding ───────────────────────────────────────────────────
//
// The rule the router enforces before it will attribute a frame to a contact.
// A frame used to be dispatched on `envelope.sender` alone, with the topic
// thrown away, so any friend could publish a `msg` naming a third party into a
// topic they shared with us and have it read as that person.

print("\n── topic ↔ sender binding ─────────────────────")

let me   = String(repeating: "a", count: 64)
let peerB = String(repeating: "b", count: 64)
let peerC = String(repeating: "c", count: 64)

guard MQTTTopics.expected(forInit: true, senderTopics: AB, me: me) == MQTTTopics.inbox(me) else {
    print("❌ an init belongs on our own inbox"); exit(1)
}
print("✓ an init is expected on OUR inbox — the only place one has business being")

guard MQTTTopics.expected(forInit: false, senderTopics: AB, me: me) == AB.conversation else {
    print("❌ a msg belongs on the conversation topic of our friendship with its sender"); exit(1)
}
print("✓ a msg is expected on the conversation topic of our friendship with its sender")

// The attack this closes: C is a friend, so C may publish on our inbox and on
// the topic we share with C. Neither is where a frame claiming to be from B may
// arrive, so both are refused.
guard MQTTTopics.expected(forInit: false, senderTopics: AB, me: me) != MQTTTopics.inbox(me) else {
    print("❌ a msg naming B must not be accepted on our inbox"); exit(1)
}
print("✓ a msg naming B is NOT expected on our inbox — anyone can publish there")

guard MQTTTopics.expected(forInit: false, senderTopics: AB, me: me) != AC.conversation else {
    print("❌ a msg naming B must not be accepted on C's conversation topic"); exit(1)
}
print("✓ …nor on the topic we share with C, which C can publish to")

guard MQTTTopics.expected(forInit: true, senderTopics: AB, me: me) != AB.conversation else {
    print("❌ an init must not be accepted on the conversation topic"); exit(1)
}
print("✓ …and an init is not accepted on the conversation topic either")

// A msg from a sender we hold no topics for has NO expected topic — it cannot
// be tied to anything, so it is dropped rather than matched against a guess.
guard MQTTTopics.expected(forInit: false, senderTopics: nil, me: me) == nil else {
    print("❌ a msg from a sender without topics must have no expected topic"); exit(1)
}
print("✓ a msg from a sender we hold no topics for matches nothing")
_ = (peerB, peerC)

// ── Empty topic levels ───────────────────────────────────────────────────────
//
// A fuzz finding, pinned (fuzz/TopicRouteTarget.swift, seed 1).
//
// An empty level is legal and meaningful in MQTT, so "u//{id}//presence",
// "/u/{id}/presence" and "u/{id}/presence/" are three DIFFERENT topics from
// "u/{id}/presence". Swift's `split(separator:)` drops empty segments by
// default, and all six spellings below classified as presence for the same peer
// — a classifier accepting inputs outside its own grammar, in the function that
// decides which conversation an inbound payload belongs to.
//
// Not reachable through the broker: the ACL grants exact topic strings and none
// of these has a grant. But the classifier should not be the part relying on
// that, and nothing else was checking.
print("")
print("── empty topic levels ─────────────────────────")
for weird in ["u/\(peerB)/presence/",
              "u//\(peerB)//presence",
              "/u/\(peerB)/presence",
              "u/\(peerB)//presence",
              "u///\(peerB)///presence/",
              "u/\(peerB)/presence//"] {
    guard case .unroutable = MQTTTopics.route(weird) else {
        print("❌ \(weird) must not route — an empty level makes it a different topic")
        exit(1)
    }
    guard MQTTTopics.peer(in: weird) == nil else {
        print("❌ \(weird) must not name a peer")
        exit(1)
    }
}
print("✓ a topic with an empty level is not the topic it resembles")

// …and the real ones still route, which is the half that would break if the
// tightening went too far.
guard case .presence(let p) = MQTTTopics.route(MQTTTopics.presence(peerB)), p == peerB,
      case .inbox = MQTTTopics.route(MQTTTopics.inbox(me)),
      case .graph = MQTTTopics.route(MQTTTopics.graph(me)) else {
    print("❌ a well-formed u/ topic stopped routing"); exit(1)
}
print("✓ …and the well-formed ones still route")

print("\nAll topic routing tests passed.")
