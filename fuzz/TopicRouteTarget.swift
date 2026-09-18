import Foundation

/// The target: `MQTTTopics.route`, on attacker-supplied topic strings.
///
/// WHY THIS SURFACE. Every inbound publish carries a topic chosen by whoever
/// sent it, and `route` is what decides which conversation the payload belongs
/// to before anything else looks at it. It runs on a string off the wire, ahead
/// of any authentication of the sender.
///
/// The broker's ACL is the barrier that stops a stranger publishing to a topic
/// at all, and `route`'s own comments lean on that — it deliberately does not
/// re-derive the friendship hash for `c/` and `h/` topics. That is a reasonable
/// division of labour, and it means the oracles here are about CONSISTENCY
/// rather than entitlement: whatever `route` decides, the rest of the app acts
/// on, so the decision has to be total, deterministic, and in agreement with the
/// other functions that read the same string.
///
/// THREE ORACLES:
///
///   A. TOTAL. `route` returns for every input. Swift traps on an out-of-bounds
///      index, on `Int` overflow and on a force-unwrapped nil, so "the process
///      is alive" is a real oracle — and a crash is a remote DoS, since the
///      topic arrives before the client can decide whether it trusts the sender.
///
///   B. THE NAMED PEER IS THE SEGMENT. When `route` says `.presence(peerID: p)`,
///      `p` must be exactly the middle segment of the topic and must be a
///      well-formed client id. `route` and `peer(in:)` read the same string by
///      different paths — one splits and switches, the other splits and
///      validates — and if they ever disagree about which peer a topic names,
///      presence for one contact is attributed to another.
///
///   C. THE APP'S OWN TOPICS ROUND-TRIP. Whatever the builders produce must
///      classify back to the kind that built it, and `expected(forInit:...)`
///      must agree. This is the binding that makes "a msg on the conversation
///      topic corroborates its sender" true; if a built topic ever routed to a
///      different kind, the corroboration silently stops happening.
///
/// What this CANNOT check is entitlement — that a peer may publish here at all.
/// That lives in the broker's SQL authorizer and is exercised by
/// services/server/test/e2e/mqtt.test.ts ("the topic ACL refuses a stranger").
func fuzzTopicRoute(_ input: Data) {
    // Topics are text. A non-UTF8 input is not a topic the transport could have
    // delivered, so decode losslessly and skip what cannot be one — feeding
    // replacement characters would fuzz String's decoder, not the router.
    guard let topic = String(data: input, encoding: .utf8) else { return }

    let verdict = MQTTTopics.route(topic)

    // ORACLE A is implicit: reaching this line means route returned.

    // Deterministic. Cheap, and it catches a route that ever starts depending on
    // anything but its argument.
    precondition(MQTTTopics.route(topic) == verdict,
                 "route is not deterministic for \(topic.debugDescription)")

    // ORACLE B.
    let segments = topic.split(separator: "/", omittingEmptySubsequences: false)
    switch verdict {
    case .presence(let peerID):
        precondition(segments.count == 3,
                     "presence route on a topic without three segments: \(topic.debugDescription)")
        precondition(String(segments[1]) == peerID,
                     "presence peerID \(peerID.debugDescription) is not the middle segment of \(topic.debugDescription)")
        precondition(PeerID.isWellFormed(peerID),
                     "presence peerID \(peerID.debugDescription) is not a well-formed client id")
        precondition(MQTTTopics.peer(in: topic) == peerID,
                     "route and peer(in:) disagree about \(topic.debugDescription)")

    case .inbox, .graph:
        // Same three-segment shape, and peer(in:) must be able to name it.
        precondition(segments.count == 3, "u/ route on a topic without three segments")
        precondition(MQTTTopics.peer(in: topic) != nil,
                     "a routed u/ topic whose peer cannot be read: \(topic.debugDescription)")

    case .conversation:
        precondition(topic.hasPrefix("c/"), "conversation route on \(topic.debugDescription)")
    case .handshake:
        precondition(topic.hasPrefix("h/"), "handshake route on \(topic.debugDescription)")
    case .unroutable:
        break
    }

    // Whatever peer(in:) names must be the middle segment of a three-part `u/`
    // topic and a well-formed id — nothing more.
    //
    // A STRONGER ORACLE HERE WAS WRONG, and which one is worth recording. I first
    // asserted that peer(in:) may only name a peer on a topic that ROUTES, and
    // the fuzzer refuted it inside two thousand inputs with "u/<valid id>/pr©sen",
    // a mutation of the accented-kind seed. That is an unroutable topic whose
    // middle segment is a perfectly good id, and peer(in:) is documented to name
    // it: "the peer id a u/{id}/... topic names". Its one production caller —
    // MQTTService, labelling a subscribe-refused log record — WANTS the peer even
    // when the kind is unknown, which is exactly what a refusal produces.
    //
    // What must hold is that a conversation or handshake topic never names a
    // peer. Those are derived from a friendship hash, and a contact id read out
    // of one would be a conversation attributed to whoever that id belongs to.
    if let named = MQTTTopics.peer(in: topic) {
        precondition(PeerID.isWellFormed(named), "peer(in:) named a malformed id")
        precondition(segments.count == 3 && String(segments[1]) == named,
                     "peer(in:) named something other than the middle segment of \(topic.debugDescription)")
        precondition(!topic.hasPrefix("c/") && !topic.hasPrefix("h/"),
                     "peer(in:) named \(named.debugDescription) on a hash-derived topic — \(topic.debugDescription)")
    }

    // ORACLE C, driven off the fuzzed bytes so the ids vary rather than being
    // two constants. Any well-formed pair will do; the property is structural.
    let a = PeerID.sha256Hex(topic)
    let b = PeerID.sha256Hex(topic + "!")

    precondition(MQTTTopics.route(MQTTTopics.conversation(a, b)) == .conversation,
                 "a built conversation topic did not route as one")
    precondition(MQTTTopics.route(MQTTTopics.handshake(a, b)) == .handshake,
                 "a built handshake topic did not route as one")
    precondition(MQTTTopics.route(MQTTTopics.inbox(a)) == .inbox,
                 "a built inbox topic did not route as one")
    precondition(MQTTTopics.route(MQTTTopics.graph(a)) == .graph,
                 "a built graph topic did not route as one")
    precondition(MQTTTopics.route(MQTTTopics.presence(a)) == .presence(peerID: a),
                 "a built presence topic did not route to its own id")

    // Both ends must derive one topic from a pair, in either order, or two peers
    // subscribe to different topics and neither ever hears the other.
    precondition(MQTTTopics.conversation(a, b) == MQTTTopics.conversation(b, a),
                 "conversation topic is not symmetric")
    precondition(MQTTTopics.handshake(a, b) == MQTTTopics.handshake(b, a),
                 "handshake topic is not symmetric")

    // The kinds must not collide: a handshake topic is a separate grant from the
    // conversation, and that separation is what keeps a challenge off a topic
    // every friend may publish to.
    precondition(MQTTTopics.conversation(a, b) != MQTTTopics.handshake(a, b),
                 "conversation and handshake derive the same topic")
    precondition(MQTTTopics.inbox(a) != MQTTTopics.graph(a),
                 "inbox and graph derive the same topic")

    // An init is delivered to an inbox, a message to the conversation. If these
    // ever coincided, a frame that proves nothing about its sender would arrive
    // on the channel whose whole job is to corroborate one.
    precondition(MQTTTopics.expected(forInit: true, sender: b, me: a) == MQTTTopics.inbox(a),
                 "expected(init) is not the recipient's inbox")
    precondition(MQTTTopics.expected(forInit: false, sender: b, me: a) == MQTTTopics.conversation(a, b),
                 "expected(msg) is not the conversation topic")
    precondition(MQTTTopics.expected(forInit: true, sender: b, me: a)
                 != MQTTTopics.expected(forInit: false, sender: b, me: a),
                 "an init and a msg from the same peer expect the same topic")

    // describe() only ever reaches a log line, but it walks the string by hand
    // and a trap in it is still a crash on an attacker-supplied value.
    _ = MQTTTopics.describe(topic)
}
