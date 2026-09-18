import Foundation

// Tests the real MQTT 3.1.1 wire codec from Services/MQTTWireClient.swift
// (compiled in by run.sh). The transport itself needs a broker; the packet
// coding is pure, and it is where a protocol bug would hide — a byte wrong in
// CONNECT and EMQX just closes the socket with no explanation.

var failures = 0
func check(_ label: String, _ condition: Bool) {
    if condition { print("  ✓ \(label)") }
    else { print("  ✗ \(label)"); failures += 1 }
}
func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

print("MQTT remaining-length varint")
for value in [0, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, 268_435_455] {
    let encoded = MQTTCodec.encodeLength(value)
    var framed = Data([0x00])           // a fixed-header byte, as in a real packet
    framed.append(encoded)
    check("\(value) round-trips (\(encoded.count) byte(s))",
          MQTTCodec.decodeLength(framed, from: 1)
            == .complete(value: value, bytes: encoded.count))
}
check("127 encodes in one byte", MQTTCodec.encodeLength(127) == Data([0x7F]))
check("128 encodes as 0x80 0x01", MQTTCodec.encodeLength(128) == Data([0x80, 0x01]))
check("an incomplete varint says so", MQTTCodec.decodeLength(Data([0x00, 0x80]), from: 1) == .incomplete)

// The distinction the old two-state `nil` could not make. "More than four
// continuation bytes" is malformed and the stream is finished; "the length is
// not all here yet" is ordinary. Both used to return nil, both callers read nil
// as "wait", and so five continuation bytes wedged the client forever: nothing
// parsed, the buffer grew without bound, and keepalive kept the link healthy.
check("five continuation bytes is MALFORMED, not incomplete",
      MQTTCodec.decodeLength(Data([0x00, 0x80, 0x80, 0x80, 0x80, 0x01]), from: 1) == .malformed)
check("…and four is still a legal prefix",
      MQTTCodec.decodeLength(Data([0x00, 0xFF, 0xFF, 0xFF, 0x7F]), from: 1)
        == .complete(value: 268_435_455, bytes: 4))

print("")
print("replay state across identities")
// A profile switch reuses this object with a new clientID. Anything still
// awaiting a PUBACK belongs to the account we just left, and re-sending it is
// what put the app in a reconnect loop: EMQX runs deny_action = disconnect, so
// one DUP publish onto the old profile's topic drops the fresh connection right
// after CONNACK, every time.
let wire = MQTTWireClient()
let willPayload = Data(#"{"s":"offline"}"#.utf8)

wire.adoptIdentity("pk-a")
wire.publish("u/pk-a/presence", payload: willPayload, qos: 1, retained: true)
wire.publish("c/hash-a-friend", payload: Data("ciphertext".utf8), qos: 1, retained: false)
check("QoS-1 publishes are held for replay", wire.inFlightPublishCount == 2)

wire.adoptIdentity("pk-a")
check("the same identity keeps them — a blip must not lose a message",
      wire.inFlightPublishCount == 2)

wire.adoptIdentity("pk-b")
check("a different identity drops them", wire.inFlightPublishCount == 0)

// QoS 0 is fire-and-forget and was never in the replay set to begin with.
wire.publish("u/pk-b/presence", payload: willPayload, qos: 0, retained: true)
check("QoS-0 publishes are not held", wire.inFlightPublishCount == 0)

print("")
print("CONNECT")
let connect = MQTTCodec.connect(clientID: "pk-abc", username: "pk-abc", password: "tok",
                                willTopic: "u/pk-abc/presence",
                                willPayload: Data(#"{"s":"offline"}"#.utf8),
                                willRetain: true, keepAlive: 30, cleanSession: false)
check("packet type is CONNECT", connect.first == 0x10)
var connectBuf = connect
let connectPacket = MQTTCodec.packetIfAny(from: &connectBuf)
check("frames as exactly one packet", connectPacket != nil && connectBuf.isEmpty)
if let p = connectPacket {
    let body = [UInt8](p.body)
    check("protocol name is MQTT", Array(body[0..<6]) == [0x00, 0x04, 0x4D, 0x51, 0x54, 0x54])
    check("protocol level is 4 (3.1.1)", body[6] == 0x04)
    // username | password | will-retain | will-QoS-1 | will | clean(off)
    let flags = body[7]
    check("username flag set", flags & 0x80 != 0)
    check("password flag set", flags & 0x40 != 0)
    check("will-retain flag set", flags & 0x20 != 0)
    check("will QoS is 1", (flags >> 3) & 0x03 == 1)
    check("will flag set", flags & 0x04 != 0)
    check("clean-session is OFF (offline queue)", flags & 0x02 == 0)
    check("keepalive is 30s", body[8] == 0x00 && body[9] == 0x1E)
    // payload: clientID, willTopic, willPayload, username, password
    check("client id leads the payload", Array(body[10..<12]) == [0x00, 0x06])
}

print("")
print("PUBLISH")
let payload = Data("ciphertext".utf8)
var pubBuf = MQTTCodec.publish(topic: "c/deadbeef", payload: payload, qos: 1,
                               retained: false, packetID: 7)
if let p = MQTTCodec.packetIfAny(from: &pubBuf), let parsed = MQTTCodec.parsePublish(p) {
    check("topic survives the round trip", parsed.topic == "c/deadbeef")
    check("packet id survives", parsed.packetID == 7)
    check("payload is byte-identical", parsed.payload == payload)
    check("QoS 1 is on the wire", (p.flags >> 1) & 0x03 == 1)
    check("retain bit is clear", p.flags & 0x01 == 0)
} else {
    check("QoS-1 PUBLISH parses", false)
}

var retainedBuf = MQTTCodec.publish(topic: "u/pk/presence", payload: Data(#"{"s":"online"}"#.utf8),
                                    qos: 1, retained: true, packetID: 9)
if let p = MQTTCodec.packetIfAny(from: &retainedBuf) {
    check("retain bit is set for presence", p.flags & 0x01 == 1)
}

var qos0Buf = MQTTCodec.publish(topic: "c/x", payload: payload, qos: 0, retained: false, packetID: nil)
if let p = MQTTCodec.packetIfAny(from: &qos0Buf), let parsed = MQTTCodec.parsePublish(p) {
    check("QoS 0 carries no packet id", parsed.packetID == nil && parsed.payload == payload)
}

print("")
print("Framing across WebSocket boundaries")
// A WS frame may carry a partial packet, several packets, or both.
var stream = Data()
stream.append(MQTTCodec.publish(topic: "c/1", payload: Data("one".utf8), qos: 1, retained: false, packetID: 1))
stream.append(MQTTCodec.publish(topic: "c/2", payload: Data("two".utf8), qos: 1, retained: false, packetID: 2))
var drained: [String] = []
while let p = MQTTCodec.packetIfAny(from: &stream) {
    if let parsed = MQTTCodec.parsePublish(p) { drained.append(parsed.topic) }
}
check("two packets in one buffer both drain", drained == ["c/1", "c/2"])

var partial = MQTTCodec.publish(topic: "c/3", payload: Data("three".utf8), qos: 1, retained: false, packetID: 3)
let tail = partial.suffix(4)
partial.removeLast(4)
check("a partial packet yields nothing", MQTTCodec.nextPacket(from: &partial) == .incomplete)
partial.append(contentsOf: tail)
check("…and parses once the rest arrives", MQTTCodec.parsePublish(MQTTCodec.packetIfAny(from: &partial)!)?.topic == "c/3")

// A big payload crosses the 2-byte remaining-length boundary.
let big = Data(repeating: 0xAB, count: 40_000)
var bigBuf = MQTTCodec.publish(topic: "c/big", payload: big, qos: 1, retained: false, packetID: 4)
check("40 KB payload round-trips",
      MQTTCodec.parsePublish(MQTTCodec.packetIfAny(from: &bigBuf)!)?.payload == big)

print("")
print("Packet size ceiling")
// The largest frame this protocol can produce is an `init`, around 82 kB. It has
// to keep working — a ceiling set below a real frame bricks the client from the
// client side, where no server change can rescue it.
let initSized = Data(repeating: 0xCD, count: 82_000)
var initBuf = MQTTCodec.publish(topic: "u/\(String(repeating: "a", count: 64))/inbox",
                                payload: initSized, qos: 1, retained: false, packetID: 5)
check("an 82 KB init still parses",
      MQTTCodec.parsePublish(MQTTCodec.packetIfAny(from: &initBuf)!)?.payload == initSized)

// A header claiming more than the ceiling is refused on the CLAIM — before any
// of it is buffered. Four bytes of remaining-length permit 268 MB, and `ingest`
// used to accumulate toward it with no signal at all.
var hugeClaim = Data([0x30])                       // PUBLISH, QoS 0
hugeClaim.append(MQTTCodec.encodeLength(200_000_000))
hugeClaim.append(Data(repeating: 0, count: 8))     // nowhere near what it claims
if case .malformed = MQTTCodec.nextPacket(from: &hugeClaim) {
    check("a 200 MB claim is refused rather than buffered", true)
} else {
    check("a 200 MB claim is refused rather than buffered", false)
}
// 1 fixed-header byte + a 4-byte remaining-length + the 8 bytes we actually fed.
// Nothing was consumed and nothing was accumulated: the refusal is a decision
// about the CLAIM, taken before the first byte of the body is waited for.
check("…and refused on 13 bytes, not on 200 MB of buffering", hugeClaim.count == 13)

// Right at the boundary, both sides of it.
for (size, shouldPass) in [(MQTTCodec.maxPacketBytes - 8, true), (MQTTCodec.maxPacketBytes + 1, false)] {
    var buf = Data([0x30])
    buf.append(MQTTCodec.encodeLength(size))
    buf.append(Data(repeating: 0, count: 4))       // deliberately short
    let verdict = MQTTCodec.nextPacket(from: &buf)
    let refused: Bool = { if case .malformed = verdict { return true }; return false }()
    check("a \(size)-byte claim is \(shouldPass ? "allowed to continue" : "refused")",
          refused == !shouldPass)
}

print("")
print("SUBSCRIBE / UNSUBSCRIBE / CONNACK")
var subBuf = MQTTCodec.subscribe(topic: "c/deadbeef", qos: 1, packetID: 11)
check("SUBSCRIBE sets the reserved 0010 flags", subBuf.first == 0x82)
if let p = MQTTCodec.packetIfAny(from: &subBuf) {
    let body = [UInt8](p.body)
    check("packet id leads the body", body[0] == 0x00 && body[1] == 0x0B)
    check("requested QoS trails the topic", body.last == 0x01)
}
var unsubBuf = MQTTCodec.unsubscribe(topic: "c/deadbeef", packetID: 12)
check("UNSUBSCRIBE sets the reserved 0010 flags", unsubBuf.first == 0xA2)
check("UNSUBSCRIBE frames cleanly",
      MQTTCodec.packetIfAny(from: &unsubBuf) != nil && unsubBuf.isEmpty)

check("PINGREQ is two bytes", MQTTCodec.pingreq() == Data([0xC0, 0x00]))
check("DISCONNECT is two bytes", MQTTCodec.disconnect() == Data([0xE0, 0x00]))

var connackBuf = Data([0x20, 0x02, 0x00, 0x00])
if let p = MQTTCodec.packetIfAny(from: &connackBuf) {
    check("CONNACK 0 = accepted", MQTTCodec.connackCode(p) == 0)
}
var refusedBuf = Data([0x20, 0x02, 0x00, 0x05])   // 5 = not authorised (bad/used token)
if let p = MQTTCodec.packetIfAny(from: &refusedBuf) {
    check("CONNACK 5 = not authorised", MQTTCodec.connackCode(p) == 5)
}

print("")
print("SUBACK return codes")
// A broker that refuses a subscription does not error and does not stay silent:
// it SUBACKs with 0x80. This body was ignored entirely, so an ACL denial read
// as success — the app subscribed to nothing, received nothing, and logged
// nothing. Under deny_action = disconnect the broker also drops the link, which
// surfaces as a bare POSIX 57 on the next write and a reconnect loop with no
// stated cause.
if let ok = MQTTCodec.subackReturnCodes(Data([0x00, 0x2A, 0x01])) {
    check("a SUBACK names the packet it answers", ok.packetID == 42)
    check("a granted subscription reports its QoS", ok.codes == [0x01])
    check("…and nothing in it is a refusal", !ok.codes.contains { $0 >= 0x80 })
} else {
    check("a SUBACK names the packet it answers", false)
}

if let denied = MQTTCodec.subackReturnCodes(Data([0x01, 0x00, 0x80])) {
    check("0x80 is recognised as a refusal", denied.codes.contains { $0 >= 0x80 })
    check("…on the right packet id", denied.packetID == 256)
} else {
    check("0x80 is recognised as a refusal", false)
}

if let mixed = MQTTCodec.subackReturnCodes(Data([0x00, 0x07, 0x00, 0x80, 0x02])) {
    check("a multi-topic SUBACK keeps every code in order", mixed.codes == [0x00, 0x80, 0x02])
    check("…and one refusal among grants is still found",
          mixed.codes.filter { $0 >= 0x80 }.count == 1)
}

check("a truncated SUBACK is refused rather than crashing",
      MQTTCodec.subackReturnCodes(Data([0x00, 0x01])) == nil)
check("an empty SUBACK is refused rather than crashing",
      MQTTCodec.subackReturnCodes(Data()) == nil)

print("")
print("Replay policy (the self-feeding reconnect loop)")
// A publish the broker REFUSES is never acked, so it survives in the in-flight
// set and is re-sent on the next CONNACK. With deny_action = disconnect each
// replay also kills the link, so one denied packet bricks the connection
// forever: connect, replay, denied, dropped, repeat — with the backoff
// resetting every cycle because every connect genuinely succeeded.
//
// MQTT 3.1.1 has no negative acknowledgement, so the ONLY available signal is
// that the packet keeps not being acked.

check("a fresh publish is replayed", ReplayPolicy.plan(attempts: [1: 0]).replay == [1])
check("…and not abandoned", ReplayPolicy.plan(attempts: [1: 0]).abandon.isEmpty)

check("one under the bound is still replayed",
      ReplayPolicy.plan(attempts: [1: ReplayPolicy.maxReplays - 1]).replay == [1])
check("at the bound it is abandoned",
      ReplayPolicy.plan(attempts: [1: ReplayPolicy.maxReplays]).abandon == [1])
check("…and no longer replayed",
      ReplayPolicy.plan(attempts: [1: ReplayPolicy.maxReplays]).replay.isEmpty)

// The property that actually matters: a packet that never gets acked LEAVES.
// Without this the set never shrinks and the link can never come up.
var attempts: [UInt16: Int] = [7: 0]
var rounds = 0
while !attempts.isEmpty, rounds < 50 {
    let plan = ReplayPolicy.plan(attempts: attempts)
    for id in plan.abandon { attempts.removeValue(forKey: id) }
    for id in plan.replay { attempts[id]? += 1 }
    rounds += 1
}
check("a never-acked publish is eventually abandoned rather than replayed forever",
      attempts.isEmpty)
check("…within maxReplays + 1 reconnects", rounds == ReplayPolicy.maxReplays + 1)

// A poison packet must not take healthy ones with it.
let mixed = ReplayPolicy.plan(attempts: [1: 0, 2: ReplayPolicy.maxReplays, 3: 1])
check("a healthy publish survives alongside an abandoned one", mixed.replay == [1, 3])
check("…and only the exhausted one is dropped", mixed.abandon == [2])

check("an empty in-flight set plans nothing",
      ReplayPolicy.plan(attempts: [:]).replay.isEmpty && ReplayPolicy.plan(attempts: [:]).abandon.isEmpty)


// ── The write confirmation the background flip depends on ───────────────────
//
// `publish(onWrite:)` exists for one caller: iOS going to the background, which
// holds a `beginBackgroundTask` assertion open until the "I am offline" frame
// has actually left. The push-bridge wakes a device only when presence says
// offline, and it decides that ONCE, when the message is published, with no
// retry — so a flip that is merely scheduled loses the notification outright.
//
// A real socket needs a broker. What is testable here without one is the
// contract that matters most: a publish with nowhere to go must ANSWER, and
// answer false. If it stayed silent, the caller would hold an iOS background
// assertion open until the watchdog killed the app.
print("")
print("publish write-confirmation")

let idle = MQTTWireClient()
let buffered = DispatchSemaphore(value: 0)
var bufferedWritten: Bool? = nil
idle.publish("u/\(String(repeating: "a", count: 64))/presence",
             payload: Data(#"{"s":"offline"}"#.utf8),
             qos: 1, retained: true) { written in
    bufferedWritten = written
    buffered.signal()
}
check("a publish with no session calls back rather than hanging",
      buffered.wait(timeout: .now() + 2) == .success)
check("…and reports that it did NOT reach the socket", bufferedWritten == false)

// The default argument is what keeps every other call site unchanged: only the
// presence flip passes a completion, and nothing else pays for one.
idle.publish("c/\(String(repeating: "b", count: 64))",
             payload: Data("x".utf8), qos: 1, retained: false)
check("a publish without a completion still compiles and does not trap", true)

print("")
if failures > 0 {
    print("✗ \(failures) MQTT wire check(s) failed")
    exit(1)
}
print("✓ MQTT wire codec OK")
