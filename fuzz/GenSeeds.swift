import Foundation

/// Writes the seed corpus for the mqtt-wire target.
///
/// WHY SEEDS DECIDE EVERYTHING. A fuzzer starting from random bytes would spend
/// its whole run being rejected by `nextPacket`'s first two guards, and would
/// never once reach `parsePublish`. Starting from a VALID packet and breaking it
/// slightly lands deep in the parser on iteration one. Seeds buy depth, and no
/// amount of mutator cleverness substitutes for them.
///
/// These are BROKER→CLIENT packets on purpose: that is the untrusted direction.
/// Client→broker packets (CONNECT, SUBSCRIBE) are included only because the
/// codec shares primitives with the inbound path.
///
/// The encoders are reused rather than hand-writing hex, so a wire-format change
/// updates the corpus instead of silently invalidating it. Where no encoder
/// exists — CONNACK and SUBACK are things only a broker sends — the packet is
/// assembled with `MQTTCodec.packet`, which is still the real framing code.

let outDir = CommandLine.arguments.count > 1
    ? URL(fileURLWithPath: CommandLine.arguments[1])
    : URL(fileURLWithPath: "corpus/mqtt-wire")

try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

/// A syntactically valid client id: 64 lowercase hex. Topic routing checks the
/// SHAPE of this, so a seed with a malformed one would never reach the routing
/// branches.
let idA = String(repeating: "a1b2c3d4", count: 8)
let idB = String(repeating: "9f8e7d6c", count: 8)

var seeds: [String: Data] = [:]

// ── inbound: what a broker sends us ─────────────────────────────────────────
seeds["connack-accepted"] = MQTTCodec.packet(.connack, body: Data([0x00, 0x00]))
seeds["connack-refused"]  = MQTTCodec.packet(.connack, body: Data([0x00, 0x05]))

seeds["publish-qos0-conversation"] = MQTTCodec.publish(
    topic: "c/" + idA, payload: Data(#"{"v":2,"t":"msg"}"#.utf8),
    qos: 0, retained: false, packetID: nil)

seeds["publish-qos1-inbox"] = MQTTCodec.publish(
    topic: "u/\(idB)/inbox", payload: Data(#"{"v":2,"t":"init"}"#.utf8),
    qos: 1, retained: false, packetID: 0x1234)

seeds["publish-retained-presence"] = MQTTCodec.publish(
    topic: "u/\(idB)/presence", payload: Data("online".utf8),
    qos: 0, retained: true, packetID: nil)

seeds["publish-empty-payload"] = MQTTCodec.publish(
    topic: "c/" + idA, payload: Data(), qos: 0, retained: false, packetID: nil)

// SUBACK granted at QoS 1, and the 0x80 refusal that an ACL denial produces —
// the case whose absence once looked exactly like success.
seeds["suback-granted"] = MQTTCodec.packet(.suback, body: Data([0x00, 0x01, 0x01]))
seeds["suback-refused"] = MQTTCodec.packet(.suback, body: Data([0x00, 0x01, 0x80]))

seeds["puback"]   = MQTTCodec.puback(packetID: 0x1234)
seeds["pingresp"] = MQTTCodec.packet(.pingresp, body: Data())

// ── outbound: shares the framing primitives ─────────────────────────────────
seeds["connect"] = MQTTCodec.connect(
    clientID: idA, username: idA, password: "token",
    willTopic: "u/\(idA)/presence", willPayload: Data("offline".utf8),
    willRetain: true, keepAlive: 30, cleanSession: false)

seeds["subscribe"] = MQTTCodec.subscribe(topic: "c/" + idA, qos: 1, packetID: 7)

// ── multi-packet: the rolling-buffer path ───────────────────────────────────
// A WebSocket frame may carry several packets, or one and a half. Nothing above
// exercises the loop in `ingest`, so it is seeded explicitly.
var run = MQTTCodec.packet(.connack, body: Data([0x00, 0x00]))
run.append(MQTTCodec.puback(packetID: 1))
run.append(MQTTCodec.publish(topic: "c/" + idA, payload: Data("hi".utf8),
                             qos: 0, retained: false, packetID: nil))
seeds["multi-packet-run"] = run

// A complete packet followed by the first bytes of another: the state
// `nextPacket` must leave alone until the rest arrives.
var partial = MQTTCodec.puback(packetID: 2)
partial.append(contentsOf: [0x30, 0x40, 0x00])
seeds["packet-then-partial"] = partial

// A MULTI-BYTE remaining-length varint. Anything over 16,383 needs three bytes,
// which is what this is here to exercise — 20 kB reaches that edge, where the
// 300 kB this used to be only added a third of a megabyte to every clone.
seeds["large-publish"] = MQTTCodec.publish(
    topic: "c/" + idA, payload: Data(repeating: 0x41, count: 20_000),
    qos: 0, retained: false, packetID: nil)

for (name, data) in seeds.sorted(by: { $0.key < $1.key }) {
    let url = outDir.appendingPathComponent("\(name).bin")
    try? data.write(to: url)
    print(String(format: "  %-28s %6d bytes", (name as NSString).utf8String!, data.count))
}
print("\(seeds.count) seeds → \(outDir.path)")
