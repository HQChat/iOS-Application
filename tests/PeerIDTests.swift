import Foundation

// The client identifier, from the Swift side.
//
// `id = sha256(lowercase-hex(publicKey))` is what names a contact everywhere:
// the MQTT client id, the topic strings, the friend graph, the envelope's
// `sender`. FOUR implementations have to agree about it byte-for-byte — this
// one, services/server/lib/identity.ts, Postgres's `pk_digest`, and the EMQX
// authorizer query — and a disagreement is not a crash. It is a client that
// names itself something the broker holds no grant for, and gets dropped with
// `0x87 NOT AUTHORIZED` and nothing in the log about encoding.
//
// That is the exact failure this codebase has shipped twice already: the AAD
// encoding, then the auth-proof encoding. Both were one encoding decision made
// twice.
//
// So the vectors are READ, not recomputed — the same file
// services/server/test/identity.test.ts reads, and the same file it asserts
// against a live Postgres. The path arrives as argv[1] from run.sh, so a missing
// file fails loudly rather than silently asserting nothing.

print("PeerID")

guard CommandLine.arguments.count > 1 else {
    print("  ✗ no vector path given — run.sh must pass identity-vectors.json")
    exit(1)
}
guard let raw = FileManager.default.contents(atPath: CommandLine.arguments[1]),
      let V = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
      let keys = V["keys"] as? [[String: Any]],
      let friendships = V["friendships"] as? [[String: Any]] else {
    print("  ✗ could not read vectors at \(CommandLine.arguments[1])")
    exit(1)
}

check((V["version"] as? Int) == 1, "vector file is version 1")
check((V["publicKeyBytes"] as? Int) == 7237, "the vectors are sized for HQC-256")
check(keys.count >= 4, "vectors for the full-size, short and uppercase cases")

// The first vector is a REAL key. A short stand-in is what let
// `pk text PRIMARY KEY` reach production; it is not what this is pinned against.
check((keys[0]["publicKeyHex"] as? String)?.count == 7237 * 2,
      "the first vector is a full-size public key")

// --- peerId ---------------------------------------------------------------
var allMatch = true
var allWellFormed = true
for k in keys {
    guard let pk = k["publicKeyHex"] as? String, let id = k["id"] as? String else { continue }
    let label = (k["label"] as? String) ?? pk.prefix(12).description
    if PeerID.from(publicKeyHex: pk) != id {
        allMatch = false
        print("     ✗ \(label): produced \(PeerID.from(publicKeyHex: pk).prefix(16))…, expected \(id.prefix(16))…")
    }
    if !PeerID.isWellFormed(id) { allWellFormed = false }
}
check(allMatch, "PeerID.from matches the pinned id for every vector")
check(allWellFormed, "every pinned id is 64 lowercase hex")
check(PeerID.length == 64, "an id is 64 characters")

// The bytes overload has to agree with the hex one, or a caller that happens to
// hold `Data` names a different contact than one holding a `String`.
if let pk = keys[0]["publicKeyHex"] as? String, let id = keys[0]["id"] as? String {
    var bytes = Data()
    var i = pk.startIndex
    while i < pk.endIndex {
        let j = pk.index(i, offsetBy: 2)
        bytes.append(UInt8(pk[i..<j], radix: 16)!)
        i = j
    }
    check(bytes.count == 7237, "the vector key decodes to 7237 bytes")
    check(PeerID.from(publicKey: bytes) == id, "from(publicKey:) agrees with from(publicKeyHex:)")
    check(PeerID.matches(publicKey: bytes, id: id), "matches(publicKey:) agrees too")
}

// Uppercase hex names the SAME contact. Not a nicety: the wire form is
// lowercase, and a caller that sent uppercase would otherwise be a stranger —
// a different id, a different topic, no ACL row, and a broker that answers 0x87
// without saying why.
if keys.count >= 4,
   let lower = keys[2]["publicKeyHex"] as? String,
   let upper = keys[3]["publicKeyHex"] as? String {
    check(lower.uppercased() == upper, "the vectors are the same key in two cases")
    check(PeerID.from(publicKeyHex: lower) == PeerID.from(publicKeyHex: upper),
          "uppercase hex names the same client as lowercase")
}

// --- The commitment -------------------------------------------------------
//
// What the digest BUYS beyond fitting in a URL: a key can be checked against an
// id already held, so the directory carries ids, the key travels separately, and
// TOFU narrows to "trust the id you were first given".

if let realPk = keys[0]["publicKeyHex"] as? String,
   let realId = keys[0]["id"] as? String,
   let otherPk = keys[1]["publicKeyHex"] as? String {
    check(PeerID.matches(publicKeyHex: realPk, id: realId), "a key verifies against its own id")
    check(!PeerID.matches(publicKeyHex: otherPk, id: realId),
          "a different key does not verify — no second preimage survives")

    // The near-miss: one flipped hex digit, which is what a tampered directory
    // response would most plausibly look like.
    let tweaked = String(realPk.dropLast()) + (realPk.hasSuffix("0") ? "1" : "0")
    check(!PeerID.matches(publicKeyHex: tweaked, id: realId),
          "one changed character is a different key")
}

check(!PeerID.isWellFormed(""), "an empty string is not an id")
check(!PeerID.isWellFormed(String(repeating: "a", count: 63)), "63 characters is not an id")
check(!PeerID.isWellFormed(String(repeating: "a", count: 65)), "65 characters is not an id")
check(!PeerID.isWellFormed(String(repeating: "A", count: 64)), "uppercase is not the wire form")
check(!PeerID.isWellFormed(String(repeating: "g", count: 64)), "non-hex is not an id")

// --- friendshipHash -------------------------------------------------------
//
// The conversation topic. 001_schema.sql has claimed since it was written that
// this has "a Swift counterpart and a cross-impl test vector"; the counterpart
// (MQTTTopics.conversation) existed, the vector did not.
//
// Recomputed here with the same construction MQTTTopics uses, so this file can
// stay free of the MQTT stack while still pinning the value that decides
// whether two members of a friendship subscribe to the same topic at all.

func conversationTopic(_ a: String, _ b: String) -> String {
    let joined = [a, b].sorted().joined()
    return "c/" + PeerID.sha256Hex(joined)
}

var hashesMatch = true
for f in friendships {
    guard let a = f["a"] as? String, let b = f["b"] as? String,
          let topic = f["topic"] as? String else { continue }
    if conversationTopic(a, b) != topic {
        hashesMatch = false
        print("     ✗ \(a.prefix(8))…/\(b.prefix(8))…: produced \(conversationTopic(a, b).prefix(16))…, expected \(topic.prefix(16))…")
    }
}
check(hashesMatch, "the conversation topic matches the pinned vectors")

if friendships.count >= 2,
   let ab = friendships[0]["topic"] as? String,
   let ba = friendships[1]["topic"] as? String {
    // The same pair reversed. One row serves both directions only because this
    // holds — and the `id_lo < id_hi` CHECK in 004 carries COLLATE "C" for the
    // same reason.
    check(ab == ba, "the topic is order-independent")
}

if let topic = friendships[0]["topic"] as? String {
    // It used to be `c/{hash}` beside a 14474-character pk in the same ACL row.
    check(topic.count == 66, "a conversation topic is 66 characters")
}

finish()
