//
//  ProtocolLog.swift
//  DissQus (shared macOS + iOS)
//
//  A trace of first contact: what was subscribed, what arrived, which key was
//  pinned and why, when a session opened, and — the part that was missing —
//  every point where a frame was DROPPED, with the reason.
//
//  Why this exists rather than more `dlog`:
//
//    * `dlog` is `#if DEBUG`. It compiles out of exactly the builds people
//      actually run, so a TestFlight device in someone's hand produces nothing.
//      The bug this was written for — inbound inbox frames discarded by the
//      dispatcher — was invisible for that reason: the drop was an `else` that
//      did not exist, and no build anyone was running would have said so.
//    * `print` goes to stdout, which is captured only while Xcode is attached.
//
//  So: `os.Logger`, which survives Release, persists in the unified log, and can
//  be read back off a device with Console.app or `log collect` — plus an
//  in-memory ring buffer so the app can show and share the trace when no Mac is
//  attached.
//
//  ── What may be logged ──────────────────────────────────────────────────────
//
//  Redaction is by CONSTRUCTION, not by filtering: every case of `Event` takes
//  ids, counts, enum-ish reasons and booleans. There is no case that takes a
//  payload, a plaintext, a key, a token or a username, so there is no call site
//  that can pass one by mistake. Ids are truncated on the way in.
//
//  That is the same rule Observability.redact enforces on Sentry, applied where
//  it is cheaper to enforce: at the type. Security audit M2 is why `dlog` was
//  compiled out in the first place, and this file is only allowed to exist in
//  Release because it cannot carry the things M2 is about.
//

import Foundation
import os

enum ProtocolLog {

    // `Logger` writes to the unified log. Read it with:
    //   log stream --predicate 'subsystem == "chat.dissqus.app"' --level debug
    // or Console.app with the same filter, device attached or not.
    private static let log = Logger(subsystem: "chat.dissqus.app", category: "protocol")

    /// How many entries the in-app buffer keeps. First contact is a handful of
    /// events per peer; this holds a long session's worth without unbounded
    /// growth.
    private static let capacity = 500

    private static let lock = NSLock()
    private static var buffer: [Entry] = []

    struct Entry {
        let at: Date
        let line: String
    }

    /// Everything worth knowing about the first-contact path.
    ///
    /// Adding a case is how you extend this. Adding a `String` parameter that
    /// could carry user content is not — see the header.
    enum Event {
        // Link
        case connected(as: String)
        case disconnected(reason: String)
        /// Our own presence flip, and whether the frame actually left the socket.
        /// `written: false` is the interesting one: the push-bridge wakes a
        /// device only when presence says offline, so an unwritten flip means the
        /// next message arrives at a suspended app with no notification.
        case presenceAnnounced(online: Bool, written: Bool)
        /// We held an `init` and asked its sender to prove it holds the key it
        /// named. An `init` is built from public values alone, so this is the
        /// only thing that distinguishes the peer from anyone who knows of them.
        case handshakeChallenged(peer: String)
        /// We answered somebody's challenge for a handshake we started.
        case handshakeProved(peer: String)
        /// A peer proved possession, and their held `init` was opened.
        case handshakeProven(peer: String)
        /// A peer could NOT prove possession. Somebody sent an `init` naming
        /// them and does not hold their key — this is the attack, arriving.
        case handshakeFailed(peer: String)
        case subscribed(topic: TopicKind, peer: String?)
        case subscribeRefused(topic: TopicKind, peer: String?, code: Int)
        case publishReplayed(topic: String, attempt: Int)
        case publishAbandoned(topic: String, attempts: Int)

        // Inbound
        case received(route: RouteKind, bytes: Int)
        case dropped(stage: String, peerID: String?, reason: String)

        // Handshake
        case initReceived(from: String, hasSenderPk: Bool)
        case initIgnoredSessionOpen(peer: String)
        /// Both sides started a session at once; we hold the lower id and keep ours.
        case initGlareKept(peer: String)
        /// Both sides started at once; we hold the higher id and adopt theirs.
        case initGlareYielded(peer: String)
        case resent(peer: String, count: Int)
        /// A frame named somebody we had no contact row for, so the graph was
        /// pulled again rather than the frame discarded.
        case directoryResyncedForUnknownSender(peer: String)
        case sessionOpenedAsResponder(peer: String, usedOneTime: Bool)
        case sessionOpenedAsInitiator(peer: String, usedOneTime: Bool)
        case initPublished(to: String)

        // Keys
        case keyPinned(peer: String, source: KeySource)
        case keyRejected(peer: String, reason: String)
        case keyFetched(peer: String, verified: Bool)

        // Prekeys
        case prekeysPublished(count: Int, rotatedMedium: Bool)
        case prekeyPoolChecked(remaining: Int, willReplenish: Bool)

        // Messages
        case messageDecrypted(peer: String)
        case messageUndecryptable(peer: String, reason: String)

        // Directory
        case directorySynced(friends: Int, withoutSession: Int, withoutKey: Int)
    }

    enum TopicKind: String { case inbox, presence, conversation, graph, handshake }
    enum RouteKind: String { case inbox, presence, conversation, graph, handshake, unroutable }
    enum KeySource: String {
        /// Fetched from `GET /peer/{id}/key` and checked against the id.
        case directory
        /// Rode on an `init` frame as `senderPk`, checked against `sender`.
        case initFrame
    }

    // MARK: - Recording

    static func record(_ event: Event) {
        let line = render(event)
        log.debug("\(line, privacy: .public)")   // .public: nothing here is private by construction

        let entry = Entry(at: Date(), line: line)
        lock.lock()
        buffer.append(entry)
        if buffer.count > capacity { buffer.removeFirst(buffer.count - capacity) }
        lock.unlock()
    }

    /// Ids are 64 hex characters; a trace of full ones is unreadable and the
    /// prefix is enough to line an event up with `check-greet.ts` output, which
    /// prints the same 8.
    private static func s(_ id: String?) -> String {
        guard let id, !id.isEmpty else { return "—" }
        return id.count <= 8 ? id : String(id.prefix(8))
    }

    private static func render(_ e: Event) -> String {
        switch e {
        case .connected(let me):
            return "🔗 connected as \(s(me))"
        case .disconnected(let reason):
            return "🔌 disconnected — \(reason)"
        case .handshakeChallenged(let peer):
            return "🔐 held \(s(peer))'s init and asked them to prove they hold that key"
        case .handshakeProved(let peer):
            return "🔐 proved our identity to \(s(peer))"
        case .handshakeProven(let peer):
            return "✅ \(s(peer)) proved possession — their init was opened"
        case .handshakeFailed(let peer):
            return "🚨 \(s(peer)) FAILED the handshake — an init named them and the sender "
                 + "could not prove they hold that key; the init was discarded"
        case .presenceAnnounced(let online, let written):
            return written
                ? "📣 announced \(online ? "online" : "offline")"
                : "⚠️ could NOT announce \(online ? "online" : "offline") — the frame never "
                  + "reached the socket; the broker still has us marked online, so a message "
                  + "arriving now raises no push"
        case .subscribed(let kind, let peer):
            return "📥 subscribed \(kind.rawValue)\(peer.map { " \(s($0))" } ?? "")"
        case .subscribeRefused(let kind, let peer, let code):
            return "⛔️ SUBSCRIBE REFUSED \(kind.rawValue)\(peer.map { " \(s($0))" } ?? "") "
                 + "(0x\(String(code, radix: 16))) — no ACL grant; nothing will arrive on it"
        case .publishReplayed(let topic, let attempt):
            return "↻ replaying an unacked publish to \(topic) (attempt \(attempt))"
        case .publishAbandoned(let topic, let attempts):
            return "🧨 ABANDONED a publish to \(topic) after \(attempts) unacknowledged "
                 + "replays — the broker is refusing it, and re-sending it was killing "
                 + "the link on every connect"
        case .received(let route, let bytes):
            return "📨 received on \(route.rawValue) (\(bytes) bytes)"
        case .dropped(let stage, let peer, let reason):
            return "🚫 DROPPED at \(stage)\(peer.map { " for \(s($0))" } ?? "") — \(reason)"
        case .initReceived(let from, let hasPk):
            return "🤝 init from \(s(from))\(hasPk ? " (carries senderPk)" : " (no senderPk)")"
        case .initIgnoredSessionOpen(let peer):
            return "· init from \(s(peer)) ignored — session already open"
        case .initGlareKept(let peer):
            return "⚖️ simultaneous init with \(s(peer)) — keeping ours (lower id)"
        case .initGlareYielded(let peer):
            return "⚖️ simultaneous init with \(s(peer)) — yielding to theirs (higher id)"
        case .resent(let peer, let count):
            return "↺ re-sent \(count) unreceived message(s) to \(s(peer)) on the surviving session"
        case .directoryResyncedForUnknownSender(let peer):
            return "🔄 frame from an unknown \(s(peer)) — resyncing the directory before dropping it"
        case .sessionOpenedAsResponder(let peer, let ot):
            return "✅ session opened with \(s(peer)) as responder"
                 + (ot ? " (one-time prekey)" : " (medium-term only)")
        case .sessionOpenedAsInitiator(let peer, let ot):
            return "✅ session opened with \(s(peer)) as initiator"
                 + (ot ? " (one-time prekey)" : " (medium-term only)")
        case .initPublished(let to):
            return "📤 init published to \(s(to))'s inbox"
        case .keyPinned(let peer, let source):
            return "🔑 pinned \(s(peer))'s key from \(source.rawValue)"
        case .keyRejected(let peer, let reason):
            return "🚨 REFUSED a key for \(s(peer)) — \(reason)"
        case .keyFetched(let peer, let verified):
            return "🔎 fetched \(s(peer))'s key — \(verified ? "hashes to their id" : "MISMATCH")"
        case .prekeysPublished(let count, let rotated):
            return "🗝️ published \(count) one-time prekey(s)\(rotated ? " + new medium-term" : "")"
        case .prekeyPoolChecked(let remaining, let will):
            return "🗝️ pool: \(remaining) remaining\(will ? " — replenishing" : "")"
        case .messageDecrypted(let peer):
            return "💬 decrypted a message from \(s(peer))"
        case .messageUndecryptable(let peer, let reason):
            return "❌ could not decrypt from \(s(peer)) — \(reason)"
        case .directorySynced(let n, let noSession, let noKey):
            return "📇 directory: \(n) friend(s), \(noSession) without a session, \(noKey) without a key"
        }
    }

    // MARK: - Reading it back

    /// The buffer, oldest first, as timestamped lines. For the diagnostics
    /// screen and for the share sheet — this is what a user can send when the
    /// device has never been near a Mac.
    static func transcript() -> String {
        lock.lock(); let entries = buffer; lock.unlock()
        let clock = DateFormatter()
        clock.dateFormat = "HH:mm:ss.SSS"
        return entries.map { "\(clock.string(from: $0.at))  \($0.line)" }.joined(separator: "\n")
    }

    static func entries() -> [Entry] {
        lock.lock(); defer { lock.unlock() }
        return buffer
    }

    static func clear() {
        lock.lock(); buffer.removeAll(); lock.unlock()
    }
}
