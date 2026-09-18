import Foundation

// Seeds for the topic-route target: every topic the app itself builds, plus the
// shapes that sit just outside them.
//
// A mutation-only fuzzer never leaves the neighbourhood of its corpus, so the
// corpus is the reach. Real topics are what the mutator needs to corrupt into
// near-misses — a hash one character short, a fourth segment, a kind that is
// almost "presence" — because those are the inputs where a classifier is most
// likely to disagree with itself.
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "corpus/topic-route"
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

let alice = PeerID.sha256Hex("alice")
let bob   = PeerID.sha256Hex("bob")

var seeds: [String: String] = [
    "conversation":      MQTTTopics.conversation(alice, bob),
    "handshake":         MQTTTopics.handshake(alice, bob),
    "inbox":             MQTTTopics.inbox(alice),
    "graph":             MQTTTopics.graph(alice),
    "presence":          MQTTTopics.presence(alice),

    // Just outside the grammar, so the mutator starts near the boundary rather
    // than having to discover it.
    "empty":             "",
    "slash":             "/",
    "c-empty-hash":      "c/",
    "h-empty-hash":      "h/",
    "u-only":            "u/",
    "u-two-segments":    "u/\(alice)",
    "u-four-segments":   "u/\(alice)/presence/extra",
    "u-bad-id":          "u/not-a-client-id/presence",
    "u-unknown-kind":    "u/\(alice)/typing",
    "u-empty-id":        "u//presence",
    "wildcard-hash":     "u/+/presence",
    "wildcard-multi":    "u/\(alice)/#",
    "trailing-slash":    "u/\(alice)/presence/",
    "leading-slash":     "/u/\(alice)/presence",
    "uppercase-id":      "u/\(alice.uppercased())/presence",
    "id-one-short":      "u/\(String(alice.dropLast()))/presence",
    "id-one-long":       "u/\(alice)0/presence",
    "null-byte":         "u/\(alice)/pres\u{0000}ence",
    "unicode-kind":      "u/\(alice)/présence",
    "rtl-override":      "u/\(alice)/\u{202E}presence",
    "deep":              String(repeating: "u/", count: 64),
]
// A very long topic, because `describe()` walks it character by character.
seeds["long"] = "c/" + String(repeating: "ab", count: 4096)

for (name, topic) in seeds {
    try? Data(topic.utf8).write(to: URL(fileURLWithPath: out).appendingPathComponent("\(name).bin"))
}
print("wrote \(seeds.count) topic seeds to \(out)")
