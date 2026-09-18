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

/// Every topic here names CLIENT IDS — `sha256(lowercase-hex(publicKey))`, 64
/// hex characters. They named public keys, so `u/{pk}/presence` was a
/// 14484-character topic, and an `mqtt_acl` row carried one of those beside a
/// 14474-character `pk` column: ~29 kB to record one membership bit. The
/// consequence that actually bit was in the admin API, where a per-client URL at
/// that size came back `414 URI Too Long` — so unfriending never dropped a live
/// subscription, only the next authorization check.
enum MQTTTopics {
    /// Conversation topic between two client ids: `c/{friendshipHash}` where the
    /// hash is sha256 over the two ids sorted — identical to the server's
    /// crypto-utils.friendshipHash, so both ends derive the same topic. Pinned
    /// against the shared vector file (apps/apple/tests/PeerIDTests.swift).
    static func conversation(_ id1: String, _ id2: String) -> String {
        "c/" + friendshipHash(id1, id2)
    }

    /// The bare hash the conversation and handshake topics are both built from:
    /// sha256 over the two ids sorted. Named separately because it is not only a
    /// topic — `POST /report` identifies a conversation by this value, and the
    /// server derives who is in it from the same hash. Two spellings of one
    /// definition is how a report ends up naming a conversation that does not
    /// exist.
    static func friendshipHash(_ id1: String, _ id2: String) -> String {
        PeerID.sha256Hex([id1, id2].sorted().joined())
    }
    /// Where two friends prove an `init` came from the peer it names:
    /// `h/{friendshipHash}`, derived exactly like the conversation topic.
    ///
    /// A SEPARATE topic from the inbox, and that is the point. Every friend may
    /// publish to an inbox, so a challenge sitting there would be visible to —
    /// and forgeable by — precisely the attacker the exchange exists to stop.
    /// Only the two members are granted this one (DB.grantFriendTopic).
    static func handshake(_ id1: String, _ id2: String) -> String {
        "h/" + friendshipHash(id1, id2)
    }
    static func presence(_ id: String) -> String { "u/\(id)/presence" }
    static func inbox(_ id: String) -> String { "u/\(id)/inbox" }
    /// Where the server says "your friend graph moved". Subscribe-only, and
    /// ours alone — nobody else is granted anything on it.
    static func graph(_ id: String) -> String { "u/\(id)/graph" }
}

/// What an inbound topic is for. Closed on purpose: the dispatcher switches over
/// this exhaustively, so adding a topic kind without routing it will not build.
enum InboundRoute: Equatable {
    /// `u/{id}/presence` — a peer's online flag. Carries the peer's id.
    case presence(peerID: String)
    /// `c/{hash}` — an established conversation. Ordinary `msg` frames.
    case conversation
    /// `h/{hash}` — the challenge/proof exchange that authenticates an `init`.
    /// Carries no envelope and no ciphertext; see Handshake.swift.
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

    /// The ONE topic a frame of this kind, from this sender, may arrive on.
    ///
    /// The router used to attribute a frame by `envelope.sender` alone and throw
    /// the topic away — the comment on the inbox route said so outright: "routes
    /// on the ENVELOPE, not on the topic". Nothing then tied a frame to the
    /// channel that carried it, so a frame claiming `sender = B` was dispatched
    /// into B's session no matter which of our topics delivered it.
    ///
    /// That matters because of what the ACL grants. `grantFriendTopic` gives each
    /// friend `publish` on the other's inbox and `all` on the shared conversation
    /// topic, and every account is auto-friended to the helper bot — so any one
    /// accepted friend had a write channel into every one of our OTHER sessions.
    /// On its own that leaks nothing (they cannot produce a frame that decrypts),
    /// but it is the delivery vector for a forged ratchet step, and it widens the
    /// attacker set for one from "the broker" to "any friend".
    ///
    /// Both ends already send exactly this way and always have — ChatSession
    /// publishes an `init` to the peer's inbox and everything else to the shared
    /// topic, and bot.ts does the same and has enforced this rule on receive
    /// since it was written. So this is the send policy, finally checked.
    ///
    /// ⚠️ It constrains a `msg` and NOT an `init`. A `msg` topic is derived from
    /// both ids, so the channel corroborates the claim. An `init` goes to
    /// `inbox(me)` — a topic every friend is granted publish on, by
    /// construction, because that is how first contact reaches an offline peer.
    /// For an `init` this establishes only that the frame reached the right
    /// inbox, and nothing whatever about who sent it.
    ///
    /// That gap is not closeable at the transport layer, and it is the door the
    /// impersonation walked through: an `init` is built entirely from public
    /// values. What closes it is the challenge on `h/{friendshipHash}` — see
    /// Handshake.swift.
    static func expected(forInit isInit: Bool, sender: String, me: String) -> String {
        isInit ? inbox(me) : conversation(me, sender)
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
    /// topic names a friendship HASH, not a peer, so there is nothing to return.
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
        if topic.hasPrefix("h/") {
            // Same reasoning as the conversation topic below: the hash is not
            // checked here because the broker refuses a topic we are not
            // entitled to at SUBSCRIBE.
            return topic.count > 2 ? .handshake : .unroutable(reason: "empty handshake hash")
        }

        if topic.hasPrefix("c/") {
            // The hash is not checked here: a conversation topic we are not
            // entitled to is refused by the broker at SUBSCRIBE, so anything
            // arriving on one is a topic we asked for.
            return topic.count > 2 ? .conversation : .unroutable(reason: "empty conversation hash")
        }

        // `omittingEmptySubsequences: false` — an EMPTY topic level is legal and
        // meaningful in MQTT, so "u//{id}//presence", "/u/{id}/presence" and
        // "u/{id}/presence/" are three different topics from "u/{id}/presence".
        //
        // Swift's default drops empty segments, so all six of those classified as
        // presence for the same peer: a classifier accepting inputs outside its
        // own grammar, in the function that decides which conversation a payload
        // belongs to. Not reachable through the broker — the ACL grants exact
        // topic strings and none of those spellings has a grant — but the
        // classifier should not be the part relying on that. Found by
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
/// must be forgotten rather than retried: `deny_action = disconnect` means the
/// refusal also drops the link, and a topic left in the wanted set drops the
/// next connection too, and the next. The loop cannot resolve itself, because
/// the thing that would grant the topic — a person accepting an invite — needs
/// an app that stays up long enough to show them the button.
struct SubscriptionLedger {

    private(set) var wanted: [String: Int] = [:]

    /// Ask for a topic (or re-ask, once a grant finally exists).
    mutating func want(_ topic: String, qos: Int) { wanted[topic] = qos }

    /// Stop wanting a topic we chose to leave — an unfriend.
    mutating func forget(_ topic: String) { wanted.removeValue(forKey: topic) }

    /// The broker said no. Drop it: re-offering it is what turns one missing
    /// grant into an app that can never stay connected.
    mutating func refused(_ topic: String) { wanted.removeValue(forKey: topic) }

    /// Everything to (re)subscribe on a fresh session.
    var toSubscribe: [(topic: String, qos: Int)] {
        wanted.map { (topic: $0.key, qos: $0.value) }.sorted { $0.topic < $1.topic }
    }

    /// A profile switch: none of it carries over.
    mutating func removeAll() { wanted.removeAll() }
}
