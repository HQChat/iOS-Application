// The trace that survives Release, and the rule that lets it.
//
// `dlog` is `#if DEBUG`, so it compiles out of the builds people actually run —
// the bug this file was written for, inbound inbox frames discarded by the
// dispatcher, was invisible for exactly that reason. ProtocolLog exists to be
// there in Release, on a TestFlight device, with no Mac attached.
//
// Which is only acceptable because of the rule in its header: redaction is BY
// CONSTRUCTION. Every case of `Event` takes ids, counts, enum-ish reasons and
// booleans; there is no case that takes a payload, a plaintext, a key, a token or
// a username, so there is no call site that can pass one by mistake. That is
// security audit M2, enforced at the type instead of by a filter.
//
// Nothing checked the rule. A `case somethingNew(text: String)` added tomorrow
// compiles, ships in Release, and writes whatever it is handed to the unified
// log — where `log collect` will hand it to anyone with the device.

import Foundation

// ── Ids are truncated on the way in ──────────────────────────────────────────

let FULL_ID = String(repeating: "ab", count: 32)     // 64 hex, a real client id

ProtocolLog.clear()
ProtocolLog.record(.connected(as: FULL_ID))
var lines = ProtocolLog.entries().map(\.line)
check(lines.count == 1, "an event is recorded")
check(!lines[0].contains(FULL_ID), "a full 64-character id reached the log")
check(lines[0].contains(String(FULL_ID.prefix(8))), "…and the 8-character prefix is kept, for correlation")

// Every case that takes a peer id must truncate it. Enumerated by hand because
// the compiler cannot iterate an enum with associated values — and the count is
// asserted below so a new case cannot be added without this list noticing.
let idEvents: [ProtocolLog.Event] = [
    .connected(as: FULL_ID),
    .handshakeChallenged(peer: FULL_ID),
    .handshakeProved(peer: FULL_ID),
    .handshakeProven(peer: FULL_ID),
    .handshakeFailed(peer: FULL_ID),
    .subscribed(topic: .conversation, peer: FULL_ID),
    .subscribeRefused(topic: .conversation, peer: FULL_ID, code: 0x87),
    .dropped(stage: "dispatch", peerID: FULL_ID, reason: "no session"),
    .initReceived(from: FULL_ID, hasSenderPk: true),
    .initIgnoredSessionOpen(peer: FULL_ID),
    .initGlareKept(peer: FULL_ID),
    .initGlareYielded(peer: FULL_ID),
    .resent(peer: FULL_ID, count: 3),
    .directoryResyncedForUnknownSender(peer: FULL_ID),
    .sessionOpenedAsResponder(peer: FULL_ID, usedOneTime: true),
    .sessionOpenedAsInitiator(peer: FULL_ID, usedOneTime: false),
    .initPublished(to: FULL_ID),
    .keyPinned(peer: FULL_ID, source: .directory),
    .keyRejected(peer: FULL_ID, reason: "id mismatch"),
    .keyFetched(peer: FULL_ID, verified: true),
    .messageDecrypted(peer: FULL_ID),
    .messageUndecryptable(peer: FULL_ID, reason: "no key"),
]

ProtocolLog.clear()
for e in idEvents { ProtocolLog.record(e) }
lines = ProtocolLog.entries().map(\.line)
check(lines.count == idEvents.count, "every event recorded a line")
for (i, line) in lines.enumerated() {
    check(!line.contains(FULL_ID), "event \(i) carried a full id into the log: \(line)")
    check(!line.isEmpty, "event \(i) rendered an empty line")
}

// The events that carry no id at all still render.
ProtocolLog.clear()
for e: ProtocolLog.Event in [
    .disconnected(reason: "socket closed"),
    .presenceAnnounced(online: true, written: true),
    .publishReplayed(topic: "c/abc", attempt: 2),
    .publishAbandoned(topic: "c/abc", attempts: 5),
    .received(route: .conversation, bytes: 128),
    .prekeysPublished(count: 8, rotatedMedium: true),
    .prekeyPoolChecked(remaining: 3, willReplenish: true),
    .directorySynced(friends: 4, withoutSession: 1, withoutKey: 0),
] { ProtocolLog.record(e) }
check(ProtocolLog.entries().count == 8, "the id-less events record too")
for l in ProtocolLog.entries().map(\.line) { check(!l.isEmpty, "…and each renders something") }

// A nil or empty id renders as a placeholder rather than as nothing — a line
// reading "dropped —" is legible; one reading "dropped " is a bug that looks
// like a truncation.
ProtocolLog.clear()
ProtocolLog.record(.dropped(stage: "route", peerID: nil, reason: "unroutable"))
ProtocolLog.record(.dropped(stage: "route", peerID: "", reason: "unroutable"))
for l in ProtocolLog.entries().map(\.line) {
    check(l.contains("—"), "a missing id renders as a placeholder: \(l)")
}

// ── The buffer is bounded ────────────────────────────────────────────────────

// It runs for the life of the process on a device nobody is watching. Unbounded
// is the difference between a diagnostic and a memory leak.
ProtocolLog.clear()
for i in 0..<600 { ProtocolLog.record(.received(route: .inbox, bytes: i)) }
let kept = ProtocolLog.entries()
check(kept.count == 500, "the ring buffer holds its capacity, not 600 (got \\(kept.count))")
// And it drops the OLDEST, not the newest — a trace that discards what just
// happened is worthless at exactly the moment you read it.
check(kept.last!.line.contains("599"), "the most recent event survived: \\(kept.last!.line)")
check(!kept.contains { $0.line.contains(" 0 bytes") }, "the oldest events were dropped")

ProtocolLog.clear()
check(ProtocolLog.entries().isEmpty, "clear empties the buffer")

// ── The rule, enforced ───────────────────────────────────────────────────────
//
// Read from the source, because this is a property of the TYPE and there is no
// runtime value that expresses it. If a case is ever added that takes free text,
// this is what says so — and the header's claim that the file "cannot carry the
// things M2 is about" stops being an assertion nobody checks.

let source = (try? String(contentsOfFile: "../DissQus/Helpers/ProtocolLog.swift", encoding: .utf8)) ?? ""
check(!source.isEmpty, "the source was readable (this check is a source-level one)")

// The `enum Event` block, and nothing else.
if let start = source.range(of: "enum Event {"),
   let end = source.range(of: "\n    }", range: start.upperBound..<source.endIndex) {
    let body = String(source[start.upperBound..<end.lowerBound])
    let cases = body.split(separator: "\n")
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { $0.hasPrefix("case ") }
    check(cases.count >= 25, "found \\(cases.count) event cases — the list above should track them")

    // Every String parameter must be named something that cannot be user
    // content. `peer`, `from`, `to`, `as`, `stage`, `reason`, `topic` are ids and
    // enum-ish strings; `text`, `body`, `payload`, `message`, `username`, `key`,
    // `token` are not, and none may appear.
    let FORBIDDEN = ["text:", "body:", "payload:", "plaintext:", "message:",
                     "username:", "handle:", "key:", "token:", "password:", "content:"]
    for c in cases {
        for bad in FORBIDDEN {
            check(!c.contains(bad),
                  "an Event case takes `\\(bad)` — redaction here is by CONSTRUCTION, "
                  + "and this case can carry user content into a Release log: \\(c)")
        }
    }

    // `.public` is on the os.Logger call, and it is only defensible because of
    // the rule above. If the rule is ever relaxed, this is the line that has to
    // change with it.
    check(source.contains("privacy: .public"),
          "the log call declares its privacy explicitly")
}

finish()
