//
//  MQTTTopics.swift
//  DissQus (shared macOS + iOS)
//
//  The topic vocabulary, and — more importantly — the decision about what an
//  arriving topic MEANS.
//
//  That decision lived inside `MQTTService.handle` as an if/else chain ending in
//  an implicit "otherwise do nothing", and it silently discarded every frame
//  delivered to this client's own inbox. The client subscribed to `u/{me}/inbox`
//  on every connect, the broker delivered to it, and the dispatcher matched
//  neither `u/.../presence` nor the `c/` prefix — so the payload fell off the end
//  of the chain. `init` frames go to the inbox and NOWHERE else, so no client
//  could ever complete first contact: the helper bot opened a session, claimed a
//  one-time prekey, sealed the greeting and published it, and the conversation
//  stayed marked "not encrypted" forever with nothing in any log.
//
//  So the decision is a pure function over the topic string, returning a CLOSED
//  set of routes, and the dispatcher switches over it exhaustively. A new topic
//  kind is then a compile error at every place that routes one, rather than a
//  message that quietly goes nowhere. It is also testable without a socket —
//  apps/apple/tests/MQTTTopicsTests.swift.
//

import Foundation

/// A friendship's two topics, as the server handed them out.
///
/// Conversation and handshake topics are CAPABILITIES: `cv/{convo_id}` and
/// `hs/{handshake_id}` name random 256-bit ids the server mints per friendship
/// (services/server/services/db/migrations/009_friendship_topics.sql) and gives
/// only to its two members, through `/friends`. The broker allows any exact
/// `cv/…` or `hs/…` and refuses every wildcard subscription, so knowing the id
/// IS the permission (infra/deploy/emqx/acl.conf).
///
/// They used to be `c/` and `h/` + sha256 over the two sorted client ids, which
/// anybody could compute — so the only thing between a stranger and a
/// conversation was a per-topic ACL in Postgres. Nothing is derived now, and
/// there is deliberately no way to build one of these from two ids: a contact
/// without synced ids has no topic until the next directory sync gives it one.
struct FriendTopics: Equatable, Hashable, Sendable {
    let conversation: String
    let handshake: String

    /// Nil unless both ids are exactly the shape the server mints: 64 lowercase
    /// hex characters. Anything else is a server that predates 009, or a value
    /// that is not ours to put in a topic string.
    init?(convoID: String?, handshakeID: String?) {
        guard let convoID, let handshakeID,
              Self.isTopicID(convoID), Self.isTopicID(handshakeID) else { return nil }
        conversation = "cv/" + convoID
        handshake = "hs/" + handshakeID
    }

    static func isTopicID(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }
}

/// Every per-user topic here names a CLIENT ID — `sha256(lowercase-hex(publicKey))`,
/// 64 hex characters. They named public keys, so `u/{pk}/presence` was a
/// 14484-character topic, and the consequence that actually bit was in the
/// admin API, where a per-client URL at that size came back `414 URI Too Long` —
/// so unfriending never dropped a live subscription.
enum MQTTTopics {
    /// The bare friendship hash: sha256 over the two ids sorted. NOT a topic any
    /// more — `POST /report` identifies a conversation by this value, and the
    /// server derives who is in it from the same hash. Two spellings of one
    /// definition is how a report ends up naming a conversation that does not
    /// exist. Pinned against the shared vector file
    /// (apps/apple/tests/PeerIDTests.swift).
    static func friendshipHash(_ id1: String, _ id2: String) -> String {
        PeerID.sha256Hex([id1, id2].sorted().joined())
    }
    /// Owner publishes (retained + LWT); anyone who knows the id may read it.
    static func presence(_ id: String) -> String { "u/\(id)/presence" }
    /// Owner subscribes; anyone who knows the id may publish (an `init` from a
    /// sender we have no friendship with is dropped by the router).
    static func inbox(_ id: String) -> String { "u/\(id)/inbox" }
    /// Where the server says "your friend graph moved". Subscribe-only, and
    /// ours alone.
    static func graph(_ id: String) -> String { "u/\(id)/graph" }
}

/// What an inbound topic is for. Closed on purpose: the dispatcher switches over
/// this exhaustively, so adding a topic kind without routing it will not build.
enum InboundRoute: Equatable {
    /// `u/{id}/presence` — a peer's online flag. Carries the peer's id.
    case presence(peerID: String)
    /// `cv/{convo_id}` — an established conversation. Ordinary `msg` frames.
    case conversation
    /// `hs/{handshake_id}` — the challenge/proof exchange that authenticates an
    /// `init`. Carries no envelope and no ciphertext; see Handshake.swift.
    case handshake
    /// `u/{me}/inbox` — where `init` frames land, ours included. The handshake
    /// arrives here and nowhere else, which is why dropping this route cost
    /// every first contact in the deployment.
    case inbox
    /// `u/{me}/graph` — the server telling us the friend graph changed. Carries
    /// nothing but that fact; the answer is to pull `/friends` again.
    ///
    /// It exists because the graph was the one piece of state the server owned
    /// and the client could only learn by asking, on a 60-second timer. An
    /// invite therefore sat unseen until the next poll, and an `init` from a
    /// freshly accepted contact could arrive before the recipient knew who the
    /// sender was — naming a client id their directory did not contain yet.
    case graph
    /// Something we never subscribed to, or a malformed topic. Logged and
    /// dropped — deliberately, and visibly.
    case unroutable(reason: String)
}

extension MQTTTopics {

    /// The ONE topic a frame of this kind, from this sender, may arrive on —
    /// or nil when there is none, because we hold no topics for that sender.
    ///
    /// The router used to attribute a frame by `envelope.sender` alone and throw
    /// the topic away, so a frame claiming `sender = B` was dispatched into B's
    /// session no matter which of our topics delivered it. Any accepted friend
    /// — and every account is auto-friended to the helper bot — then had a
    /// write channel into every one of our OTHER sessions: the delivery vector
    /// for a forged ratchet step.
    ///
    /// Both ends already send exactly this way — ChatSession publishes an `init`
    /// to the peer's inbox and everything else to the conversation topic, and
    /// bot.ts does the same and has enforced this rule on receive since it was
    /// written. So this is the send policy, checked.
    ///
    /// ⚠️ It constrains a `msg` and NOT an `init`. A `msg` must arrive on the
    /// conversation topic of OUR friendship with its sender, so the channel
    /// corroborates the claim. An `init` goes to `inbox(me)`, which anyone who
    /// knows our id may publish to — so for an `init` this establishes nothing
    /// about who sent it. What closes that gap is the challenge on the
    /// handshake topic — see Handshake.swift.
    static func expected(forInit isInit: Bool, senderTopics: FriendTopics?, me: String) -> String? {
        isInit ? inbox(me) : senderTopics?.conversation
    }

    /// A topic, shortened for a log line: long hex runs collapse to their ends,
    /// so a trace stays readable and still lines up with the eight characters
    /// the server-side scripts print.
    static func describe(_ topic: String) -> String {
        var out = ""
        var run = ""
        func flush() {
            if run.count >= 16 { out += "\(run.prefix(8))…" } else { out += run }
            run = ""
        }
        for ch in topic {
            if ch.isHexDigit, !ch.isUppercase { run.append(ch) } else { flush(); out.append(ch) }
        }
        flush()
        return out
    }

    /// The peer id a `u/{id}/...` topic names, when it names one. A conversation
    /// topic names a random friendship id, not a peer, so there is nothing to
    /// return.
    static func peer(in topic: String) -> String? {
        // Same strictness as `route` — the two read the same string and must
        // agree on what counts as one.
        let parts = topic.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "u" else { return nil }
        let id = String(parts[1])
        return PeerID.isWellFormed(id) ? id : nil
    }
}

extension MQTTTopics {

    /// Classify an inbound topic. Pure; no I/O, no state.
    static func route(_ topic: String) -> InboundRoute {
        if topic.hasPrefix("hs/") {
            // The id is not checked against anything here: the router checks the
            // topic against the friendship's own before it acts on a frame.
            return topic.count > 3 ? .handshake : .unroutable(reason: "empty handshake id")
        }

        if topic.hasPrefix("cv/") {
            // Same: `expected(forInit:senderTopics:me:)` is where a conversation
            // topic is tied to a sender.
            return topic.count > 3 ? .conversation : .unroutable(reason: "empty conversation id")
        }

        // `omittingEmptySubsequences: false` — an EMPTY topic level is legal and
        // meaningful in MQTT, so "u//{id}//presence", "/u/{id}/presence" and
        // "u/{id}/presence/" are three different topics from "u/{id}/presence".
        //
        // Swift's default drops empty segments, so all six of those classified as
        // presence for the same peer: a classifier accepting inputs outside its
        // own grammar, in the function that decides which conversation a payload
        // belongs to. Not reachable through the broker — the ACL names exact
        // topic shapes and none of those spellings matches — but the classifier
        // should not be the part relying on that. Found by
        // fuzz/TopicRouteTarget.swift.
        let parts = topic.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "u" else {
            return .unroutable(reason: "not a u/{id}/{kind} topic")
        }
        let id = String(parts[1])
        // Checked for SHAPE, not merely for existence: a value that is not a
        // well-formed client id names nobody this app knows, and treating it as
        // a peer would show a contact that never comes online.
        guard PeerID.isWellFormed(id) else {
            return .unroutable(reason: "middle segment is not a client id")
        }

        switch parts[2] {
        case "presence": return .presence(peerID: id)
        case "inbox":    return .inbox
        case "graph":    return .graph
        default:         return .unroutable(reason: "unknown topic kind '\(parts[2])'")
        }
    }
}

/// What this client wants to be subscribed to, and what it has learned it may
/// not have.
///
/// Kept apart from the transport because the rule that matters is a bookkeeping
/// rule, and getting it wrong is invisible until the app will not connect.
///
/// A subscription is re-offered on every connect, so a topic the broker REFUSES
/// must be forgotten rather than retried. Under the old `deny_action =
/// disconnect` a refusal also dropped the link, and a topic left in the wanted
/// set dropped every connection after it. The broker only refuses the one packet
/// now (`deny_action = ignore`), but re-asking for a refused topic on every
/// reconnect is still pointless: the next directory sync is what re-asks, with
/// topics the server has actually handed out.
struct SubscriptionLedger {

    private(set) var wanted: [String: Int] = [:]

    /// Ask for a topic (or re-ask, after a directory sync names it again).
    mutating func want(_ topic: String, qos: Int) { wanted[topic] = qos }

    /// Stop wanting a topic we chose to leave — an unfriend.
    mutating func forget(_ topic: String) { wanted.removeValue(forKey: topic) }

    /// The broker said no. Drop it rather than re-offer it on every connect.
    mutating func refused(_ topic: String) { wanted.removeValue(forKey: topic) }

    /// Everything to (re)subscribe on a fresh session.
    var toSubscribe: [(topic: String, qos: Int)] {
        wanted.map { (topic: $0.key, qos: $0.value) }.sorted { $0.topic < $1.topic }
    }

    /// A profile switch: none of it carries over.
    mutating func removeAll() { wanted.removeAll() }
}
