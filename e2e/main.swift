//
//  main.swift
//  DissQus end-to-end harness
//
//  A whole interaction, through the real Swift implementation, over a bus made
//  of files: friend request → prekey claim → init → the initiator-authentication
//  handshake → five messages each way → an integrity check on the transcript.
//
//  Run it: bash apps/apple/e2e/run.sh
//
//  It took a `--v2` flag and ran the identical script on the older wire format,
//  because the whole point of the frame seam was that the version made no
//  difference above the transport. It did not, and v2 is gone.
//
//  Every packet is written to disk as hex and read back before it is parsed, so
//  a round trip through the filesystem is part of the test rather than a detail
//  the harness optimises away.
//

import Foundation

// ── Setup ────────────────────────────────────────────────────────────────────

let args = CommandLine.arguments
let outDir = URL(fileURLWithPath: args.first(where: { $0.hasPrefix("/") && $0.contains("e2e-out") })
                 ?? NSTemporaryDirectory() + "hqchat-e2e-out")

var failures: [String] = []
func check(_ ok: Bool, _ what: String) {
    print(ok ? "  ✓ \(what)" : "  ✗ \(what)")
    if !ok { failures.append(what) }
}

print("── HQChat end-to-end ──────────────────────────")
print("   real HQC (libhqc_wrap), real ratchet, real frames, real AEAD")
print("   packets: \(outDir.path)")
print("")

// --faults turns the bus from a perfect channel into a lossy one: duplicates,
// reorders and drops, all drawn from --seed so a failure replays exactly.
//
// Nothing in the protocol below is interesting over a perfect channel. The
// ratchet's skipped-key cache, the replay refusal and the out-of-order path are
// all reachable only when delivery misbehaves — and MQTT at QoS 1 promises at
// LEAST once, so duplicates are ordinary rather than exotic.
let faults: BusFaults = args.contains("--faults")
    ? BusFaults(duplicatePercent: 25, reorderPercent: 25, dropPercent: 0)
    : .none
// Enabled AFTER first contact — see the note on BusFaults. The bus starts clean.
let busSeed = UInt64(args.firstIndex(of: "--seed").flatMap { args.count > $0 + 1 ? args[$0 + 1] : nil }
                     .flatMap { UInt64($0) } ?? 1)
let bus = try FileBus(root: outDir, faults: .none, seed: busSeed)
// Printed HERE, not with the rest of the banner above: in main.swift a top-level
// `let` is a global, and reading one before its initialiser has run yields the
// zero value rather than a compile error. The banner did exactly that and
// cheerfully reported "none (perfect channel)" on a faulted run.
print("   channel: \(faults.enabled ? "\(faults.summary) from step 3, seed \(busSeed)" : faults.summary)")
let alice = try Party(name: "alice", bus: bus)
let bob = try Party(name: "bob", bus: bus)
try alice.publishPrekeys()
try bob.publishPrekeys()

// ── 1. Friend request ────────────────────────────────────────────────────────
//
// The server half — invite, accept, the mqtt_acl rows — is exercised by
// services/server/test/e2e against a real broker. The client half is the one
// that matters here: a key is pinned only if it hashes to the id that named it.

print("1. friend request")
check(alice.acceptFriend(bob.id, publicKey: bob.identityPk), "alice pins bob's key")
check(bob.acceptFriend(alice.id, publicKey: alice.identityPk), "bob pins alice's key")

// The id is a commitment, so a substituted key is arithmetic to detect.
var impostorKey = bob.identityPk
impostorKey[impostorKey.startIndex] ^= 0xff
check(!alice.acceptFriend(bob.id, publicKey: impostorKey),
      "…and a key that does not hash to that id is refused")

// The ACL, as grantFriendTopic writes it: the conversation, both inboxes, and
// the handshake topic — granted to the two members and to nobody else.
for (me, peer) in [(alice.id, bob.id), (bob.id, alice.id)] {
    bus.grant(me, MQTTTopics.conversation(me, peer))
    bus.grant(me, MQTTTopics.inbox(peer))
    bus.grant(me, MQTTTopics.inbox(me))
    bus.grant(me, MQTTTopics.handshake(me, peer))
}
check(bus.mayTouch(alice.id, MQTTTopics.handshake(alice.id, bob.id)),
      "both members are granted the handshake topic")

// ── 2. First contact ─────────────────────────────────────────────────────────

print("")
print("2. first contact")
try alice.startSession(with: bob.id, bundle: bob.bundle)
let greeting = try alice.send("hello bob, this is the first thing you get", to: bob.id)
check(bus.packets(on: MQTTTopics.inbox(bob.id)).count == 1,
      "the init went to bob's inbox, the one topic that reaches an offline peer")

// Bob reads it — and does NOT open it. It is held pending a challenge.
try bob.poll(peers: [alice.id])
check(bob.inbox.isEmpty, "bob does NOT open the init on sight — it proves nothing about its sender")
check(bus.packets(on: MQTTTopics.handshake(bob.id, alice.id)).count == 1,
      "…he challenges instead")

// Alice answers, Bob verifies, and only then is the message delivered.
try alice.poll(peers: [bob.id])
try bob.poll(peers: [alice.id])
check(bob.proven.contains(alice.id), "alice proved possession of the key she claimed")
check(bob.inbox.count == 1, "…and only then does the init open")
check(bob.inbox.first?.text == "hello bob, this is the first thing you get",
      "the greeting arrives intact")
check(bob.inbox.first?.msgId == greeting, "…under the id it was sent with")

// ── 2b. A burst before the reply (PROTO-1) ───────────────────────────────────
//
// This gap is the only place in the script where alice holds an UNANSWERED
// `pendingInit`, and that is the whole precondition — one line further down bob
// replies and it is cleared for good.
//
// `seal` attaches the init header to every frame until the peer answers, so
// everything alice sends here is still typed `init`. A receiver that already
// holds a session used to refuse those WITHOUT opening them, which threw away
// the message inside each one: the server implementation of the same rule
// delivered 1 of 3 against a real broker before it was fixed.
//
// Nothing above catches it, and step 3 below cannot: it delivers on every turn
// "so the ratchet actually flips direction rather than running as two one-way
// streams", and flipping direction is exactly what clears pendingInit. A person
// does not alternate — they send "hi", "you there?", "it's about tomorrow" — so
// this is the ordinary case that had no test.
//
// These still route to bob's INBOX rather than the conversation topic, because
// an init does, and the grants in step 1 already cover it.

print("")
print("2b. a burst before bob replies")
// Named here and folded into `sentByAlice` at step 3, so the transcript check at
// the bottom stays DERIVED. It counts `sentByAlice.count + 1` for the greeting,
// and its own comment records that a literal there broke four checks the last
// time a step was inserted above it.
let burstFromAlice = ["you there?", "it is about tomorrow"]
let second = try alice.send(burstFromAlice[0], to: bob.id)
let third = try alice.send(burstFromAlice[1], to: bob.id)
try bob.poll(peers: [alice.id])
check(bob.inbox.count == 3,
      "all three of alice's messages arrive, not just the first (bob has \(bob.inbox.count)/3)")
check(bob.inbox.map(\.text) == ["hello bob, this is the first thing you get"] + burstFromAlice,
      "…in the order she sent them")
check(Set([greeting, second, third]).count == 3
      && Set(bob.inbox.map(\.msgId)) == Set([greeting, second, third]),
      "…each under its own id, so none was collapsed into another")

// Bob replies. He already holds a session — `startAsResponder` built one from
// the init — and it has no sending chain yet, so this is the responder's first
// real ratchet step.
let reply = try bob.send("hello alice", to: alice.id)
try alice.poll(peers: [bob.id])
check(alice.inbox.count == 1 && alice.inbox.first?.text == "hello alice",
      "bob's reply opens on alice's side")
_ = reply

// ── 3. Five messages each way ────────────────────────────────────────────────

print("")
print("3. five messages each way")

// The channel stops being perfect here. Everything above established the
// session; from this point a duplicate is a QoS-1 redelivery and a reorder is
// ordinary jitter, and both must be survived rather than merely avoided.
if faults.enabled {
    bus.faults = faults
    print("   channel degraded: \(faults.summary)")
}
// Seeded with the burst from 2b: those were alice's messages too, and the
// transcript check at the bottom compares this list against what bob received.
var sentByAlice: [String] = burstFromAlice
var sentByBob: [String] = []
for i in 1...5 {
    let a = "alice #\(i): the quick brown fox — café 🔒 \(String(repeating: "x", count: i * 7))"
    let b = "bob #\(i): réponse — 🛰️ \(String(repeating: "y", count: i * 11))"
    sentByAlice.append(a)
    sentByBob.append(b)
    _ = try alice.send(a, to: bob.id)
    _ = try bob.send(b, to: alice.id)
    // Deliver on every turn, so the ratchet actually flips direction rather than
    // running as two one-way streams.
    try alice.poll(peers: [bob.id])
    try bob.poll(peers: [alice.id])
}

// ── 3b. A restart, mid-conversation ──────────────────────────────────────────
//
// Both sessions go out through JSON and come back, exactly as the Keychain
// round-trips them on every save and every launch. Then the conversation
// continues on the restored state.
//
// This is the first thing here to exercise the PERSISTED shape. Every check
// above held one session in memory for its whole life, so a field that failed to
// survive encoding — or a decode that quietly produced a different state — would
// not have surfaced until a real client restarted mid-conversation. The cost of
// getting that wrong is not a dropped message: a session that cannot be re-read
// is the conversation gone, and a re-`init` from a peer who has already heard
// from you is refused as a replay, so there is no recovery path.

print("")
print("3b. a restart, mid-conversation")

// Put a key in the skipped cache, and leave it there.
//
// Without this the restart carries an EMPTY cache, and "the skipped-key cache
// survived" compares 0 to 0. A reorder does not help: a held packet is delivered
// on the next poll and its key is consumed and removed, so the cache is
// transiently non-empty and empty again by the time anything looks.
//
// A permanently missing message is what leaves a key behind — which is exactly
// what the cache is for, and what an offline or lossy peer produces. Dropped
// deterministically rather than by chance, so the assertion below means the same
// thing on every run.
let dropAll = bus.faults
bus.faults = BusFaults(duplicatePercent: 0, reorderPercent: 0, dropPercent: 100)
_ = try alice.send("this one never arrives", to: bob.id)
try bob.poll(peers: [alice.id])
bus.faults = dropAll

sentByAlice.append("this one does")
_ = try alice.send("this one does", to: bob.id)
var skipTries = 0
while bob.inbox.last?.text != "this one does" && skipTries < 10 {
    try bob.poll(peers: [alice.id])
    skipTries += 1
}
check(bob.inbox.last?.text == "this one does",
      "a message after a lost one still opens")
check((bob.sessions[alice.id]?.skipped.count ?? 0) > 0,
      "…and the lost one's key is held for it")

let aliceBefore = alice.sessions[bob.id]
let bobBefore = bob.sessions[alice.id]
try alice.reloadSessionsThroughStorage()
try bob.reloadSessionsThroughStorage()
check(alice.sessions[bob.id] != nil && bob.sessions[alice.id] != nil,
      "both sessions survive a JSON round trip")
// Printed, because "the cache survived" compares 0 to 0 and proves nothing when
// the cache is empty — the same trap as an oracle that never reaches its state.
print("     bob carries skipped=\(bobBefore?.skipped.count ?? -1) seenChains=\(bobBefore?.seenChains.count ?? -1)")
check(bob.sessions[alice.id]?.skipped.count == bobBefore?.skipped.count,
      "…including the skipped-key cache, which is not empty")
check(alice.sessions[bob.id]?.seenChains == aliceBefore?.seenChains,
      "…and the retired-chain list that stops a replayed step")
check(bob.sessions[alice.id]?.skipped == bobBefore?.skipped,
      "…byte for byte, keys included")

let afterRestart = "after the restart"
sentByAlice.append(afterRestart)
_ = try alice.send(afterRestart, to: bob.id)
var restartTries = 0
while bob.inbox.last?.text != afterRestart && restartTries < 10 {
    try bob.poll(peers: [alice.id])
    restartTries += 1
}
check(bob.inbox.last?.text == afterRestart,
      "the conversation continues on the restored session")

let backAgain = "and back again"
sentByBob.append(backAgain)
_ = try bob.send(backAgain, to: alice.id)
restartTries = 0
while alice.inbox.last?.text != backAgain && restartTries < 10 {
    try alice.poll(peers: [bob.id])
    restartTries += 1
}
check(alice.inbox.last?.text == backAgain, "…in both directions")

// ── 4. Integrity ─────────────────────────────────────────────────────────────

print("")
print("4. integrity")

// DRAIN THE CHANNEL before counting anything.
//
// A reorder holds a packet back for delivery on the subscriber's next receive,
// so with faults on there can be packets still in flight when the loop above
// ends. Counting then measures the hold rather than the protocol — and that is
// not hypothetical: the first fault-injected run failed four checks for exactly
// this reason, all of them totals, with nothing wrong in the ratchet.
//
// Polling until the bus stops holding anything is what a real client does; it
// keeps receiving. Bounded so a bug here cannot hang the suite.
if bus.faults.enabled {
    var drains = 0
    while bus.heldCount > 0 && drains < 10 {
        try alice.poll(peers: [bob.id])
        try bob.poll(peers: [alice.id])
        drains += 1
    }
    check(bus.heldCount == 0, "the channel drained (\(drains) extra poll(s))")

    // A fault injector that injected nothing is indistinguishable from a clean
    // run, and would report the same green. Same failure mode as a differential
    // fuzzer that cannot detect a divergence: the result only means something if
    // the thing under test was actually provoked.
    check(!bus.faultLog.isEmpty,
          "the channel actually misbehaved (\(bus.faultLog.count) fault(s) applied)")
    for line in bus.faultLog { print("     \(line)") }
}

let bobGot = bob.inbox.filter { $0.from == alice.id }.map(\.text)
let aliceGot = alice.inbox.filter { $0.from == bob.id }.map(\.text)

// Derived from what was actually sent, not hardcoded. The literal 6 was right
// for exactly the scenario that existed when it was written, and adding a step
// above silently made four checks fail for bookkeeping reasons rather than
// protocol ones. `+ 1` is the greeting, which is sent before the transcript
// starts being recorded.
check(bobGot.count == sentByAlice.count + 1,
      "bob received every message alice sent (\(sentByAlice.count) + the greeting)")
check(aliceGot.count == sentByBob.count + 1,
      "alice received every message bob sent (\(sentByBob.count) + the reply)")

// The dropped one must NOT be there — a scenario that lost a message and then
// counted it as delivered would be reporting the opposite of what happened.
check(!bobGot.contains("this one never arrives"),
      "…and not the one the channel dropped")
check(Array(bobGot.dropFirst()) == sentByAlice, "every message alice sent arrived, in order, byte-identical")
check(Array(aliceGot.dropFirst()) == sentByBob, "every message bob sent arrived, in order, byte-identical")

// Multi-byte text is the case a length bound gets wrong: the msgId rules were
// counting graphemes on one side and UTF-16 units on the other.
check(bobGot.contains { $0.contains("café 🔒") }, "multi-byte text survives the round trip")
check(aliceGot.contains { $0.contains("🛰️") }, "…in both directions")

// No message was delivered twice — the ratchet refuses a consumed position.
let bobIds = bob.inbox.map(\.msgId)
check(Set(bobIds).count == bobIds.count, "no message was delivered twice")

// A replay of a real frame is refused, and does not disturb the session.
let lastFromAlice = bus.packets(on: MQTTTopics.conversation(alice.id, bob.id))
    .last { $0.publisher == alice.id }
if let replay = lastFromAlice {
    let before = bob.inbox.count
    try bus.publish(replay.payload, to: replay.topic, from: alice.id)
    try bob.poll(peers: [alice.id])
    check(bob.inbox.count == before, "a byte-identical replay yields nothing")
    _ = try alice.send("still working", to: bob.id)
    try bob.poll(peers: [alice.id])
    // One poll is enough on a clean channel; with faults a reorder can hold this
    // message back for the next one. The claim is that the session still works
    // after a replay, not that delivery is instant.
    var tries = 0
    while bob.inbox.last?.text != "still working" && tries < 10 {
        try bob.poll(peers: [alice.id])
        tries += 1
    }
    check(bob.inbox.last?.text == "still working", "…and the conversation survives it")
} else {
    check(false, "found a frame to replay")
}

// Every packet on the bus round-tripped through a file and matched its digest —
// `FileBus.receive` re-reads and compares, so reaching here means it held.
check(bus.packetCount >= 14, "every packet went through the filesystem (\(bus.packetCount) of them)")
// Drops are recorded rather than swallowed, because a silent drop is the
// failure mode this protocol keeps re-learning. Two are EXPECTED here and the
// test would be weaker without them: the impostor key offered in step 1, and
// the replay in step 4 — which the ratchet refuses by design, and which shows
// up as "no key for this position".
let expectedDrop = { (d: String) in
    d.contains("does not hash to") || d.contains("no key for")
}
let aliceUnexpected = alice.drops.filter { !expectedDrop($0) }
let bobUnexpected = bob.drops.filter { !expectedDrop($0) }
check(aliceUnexpected.isEmpty, "alice dropped nothing unexpected\(aliceUnexpected.isEmpty ? "" : ": \(aliceUnexpected)")")
check(bobUnexpected.isEmpty, "bob dropped nothing unexpected\(bobUnexpected.isEmpty ? "" : ": \(bobUnexpected)")")
check(alice.drops.contains { $0.contains("does not hash to") },
      "…and the impostor key WAS refused, on the record")
check(bob.drops.contains { $0.contains("no key for") },
      "…and the replay WAS refused, on the record")

try bus.writeManifest()

print("")
print("── handshake transcript ───────────────────────")
for e in (alice.handshakeEvents + bob.handshakeEvents) { print("   \(e)") }
print("")
print("── packets ────────────────────────────────────")
print("   \(bus.packetCount) written and read back as hex, digests verified")
print("   manifest: \(outDir.appendingPathComponent("manifest.tsv").path)")

print("")
if failures.isEmpty {
    print("✅ END-TO-END PASSED")
    exit(0)
} else {
    print("❌ \(failures.count) CHECK(S) FAILED")
    for f in failures { print("   · \(f)") }
    exit(1)
}
