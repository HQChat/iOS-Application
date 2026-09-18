// The inbound parser's refusals — every byte here came off a socket.
//
// MQTTWireTests covers what the codec does with well-formed packets. This covers
// what it does with the rest, which is the half that matters for a parser: a
// WebSocket frame may carry a partial packet, several packets, or both, and the
// bytes are whatever arrived.
//
// The three cases of `NextPacket` exist because collapsing them is the bug. A
// hostile remaining-length that reads as "nothing yet" leaves the client waiting
// and buffering forever, which is exactly how a claimed length becomes an
// unbounded allocation. `.malformed` is the third case so the caller must decide.

import Foundation

func packetBytes(_ header: UInt8, _ body: Data) -> Data {
    Data([header]) + MQTTCodec.encodeLength(body.count) + body
}

// ── The remaining-length varint ──────────────────────────────────────────────

// Round trip across every boundary the encoding has: 1, 2, 3 and 4 byte forms.
for n in [0, 1, 127, 128, 129, 16_383, 16_384, 2_097_151, 2_097_152, 268_435_455] {
    let enc = MQTTCodec.encodeLength(n)
    let dec = MQTTCodec.decodeLength(Data([0x30]) + enc, from: 1)
    if case .complete(let value, let bytes) = dec {
        check(value == n, "length \(n) round-trips")
        check(bytes == enc.count, "length \(n) reports the \(enc.count) bytes it used")
    } else {
        check(false, "length \(n) did not decode")
    }
}

// A varint with the continuation bit set on all four bytes has no fifth byte to
// run into — it must be refused rather than read past the end.
check(MQTTCodec.decodeLength(Data([0x30, 0xFF, 0xFF, 0xFF, 0xFF]), from: 1) == .malformed,
      "five continuation bytes is malformed, not a very large number")
check(MQTTCodec.decodeLength(Data([0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]), from: 1) == .malformed,
      "…and a fifth byte does not rescue it")

// Truncated mid-varint is INCOMPLETE, not malformed: the rest may still arrive.
for truncated in [Data([0x30]), Data([0x30, 0x80]), Data([0x30, 0x80, 0x80]), Data([0x30, 0x80, 0x80, 0x80])] {
    check(MQTTCodec.decodeLength(truncated, from: 1) != .malformed,
          "a varint cut after \(truncated.count - 1) byte(s) is incomplete, not malformed")
}

// ── nextPacket, and the three answers it can give ────────────────────────────

var empty = Data()
check(MQTTCodec.nextPacket(from: &empty) == .incomplete, "an empty buffer is incomplete")
var oneByte = Data([0x30])
check(MQTTCodec.nextPacket(from: &oneByte) == .incomplete, "one byte is incomplete")
check(oneByte.count == 1, "…and nothing was consumed")

// A packet whose body has not all arrived: keep the buffer intact.
var partial = packetBytes(0x30, Data(repeating: 0x41, count: 50)).prefix(20)
var partialBuf = Data(partial)
check(MQTTCodec.nextPacket(from: &partialBuf) == .incomplete, "a half-arrived packet is incomplete")
check(partialBuf.count == 20, "…and the bytes are kept for the rest to join")

// The hostile length. `total` is checked against the CLAIM, before a single byte
// of it is buffered — the point is to refuse the accumulation, not to notice it
// afterwards, and a client that waited would sit there allocating.
var huge = Data([0x30]) + MQTTCodec.encodeLength(268_435_455)
if case .malformed(let reason) = MQTTCodec.nextPacket(from: &huge) {
    check(reason.contains("over the"), "a 256 MB claim is refused: \(reason)")
    check(reason.contains("268435455") || reason.contains("bytes"), "…and the reason names the size")
} else {
    check(false, "a packet claiming 256 MB was not refused")
}

// Malformed must NOT read as incomplete. That collapse is the bug the third case
// exists to prevent, and it is invisible: the client simply never progresses.
var badVarint = Data([0x30, 0xFF, 0xFF, 0xFF, 0xFF])
let verdict = MQTTCodec.nextPacket(from: &badVarint)
check(verdict != .incomplete, "a broken varint is not reported as 'wait for more'")
if case .malformed = verdict {
    check(true, "…it is malformed")
} else {
    check(false, "a broken varint gave \(verdict)")
}

// Two packets in one buffer, which is ordinary on a WebSocket.
var pair = packetBytes(0x30, Data([1, 2, 3])) + packetBytes(0xD0, Data())
guard case .packet(let first) = MQTTCodec.nextPacket(from: &pair) else {
    check(false, "the first of two packets did not parse"); exit(1)
}
check(first.body == Data([1, 2, 3]), "the first packet's body is its own")
guard case .packet(let second) = MQTTCodec.nextPacket(from: &pair) else {
    check(false, "the second packet did not parse"); exit(1)
}
check(second.header == 0xD0, "the second packet follows immediately")
check(pair.isEmpty, "both were consumed")
check(MQTTCodec.nextPacket(from: &pair) == .incomplete, "and the buffer is empty, not malformed")

// A zero-length packet is legal (PINGRESP, DISCONNECT) and must not read as
// incomplete forever.
var ping = packetBytes(0xD0, Data())
if case .packet(let p) = MQTTCodec.nextPacket(from: &ping) {
    check(p.body.isEmpty, "a bodyless packet parses")
} else {
    check(false, "a zero-length packet did not parse")
}

// ── PUBLISH, where the topic length is attacker-supplied ─────────────────────

// A topic length longer than the body. Reading it would run off the end.
check(MQTTCodec.parsePublish(MQTTPacket(header: 0x30, body: Data([0xFF, 0xFF, 0x41]))) == nil,
      "a topic length past the end of the body is refused")
check(MQTTCodec.parsePublish(MQTTPacket(header: 0x30, body: Data([0x00, 0x05, 0x41]))) == nil,
      "…including by one byte")
check(MQTTCodec.parsePublish(MQTTPacket(header: 0x30, body: Data())) == nil, "an empty body is refused")
check(MQTTCodec.parsePublish(MQTTPacket(header: 0x30, body: Data([0x00]))) == nil, "one byte is refused")

// A topic that is not UTF-8. MQTT says topics are UTF-8; a lone continuation
// byte is not, and `String(data:encoding:)` returning nil is the check.
check(MQTTCodec.parsePublish(MQTTPacket(header: 0x30, body: Data([0x00, 0x01, 0xFF]))) == nil,
      "a topic that is not UTF-8 is refused rather than lossily converted")

// QoS 1 without room for the packet id.
let qos1Header: UInt8 = 0x32   // PUBLISH, qos 1
check(MQTTCodec.parsePublish(MQTTPacket(header: qos1Header, body: Data([0x00, 0x01, 0x61]))) == nil,
      "a QoS-1 publish with no room for its packet id is refused")

// The well-formed cases, so the refusals above are not simply "always nil".
if let ok = MQTTCodec.parsePublish(MQTTPacket(header: 0x30, body: Data([0x00, 0x01, 0x61]) + Data([9, 9]))) {
    check(ok.topic == "a", "a QoS-0 publish yields its topic")
    check(ok.packetID == nil, "…and carries no packet id")
    check(ok.payload == Data([9, 9]), "…and its payload")
}
if let ok = MQTTCodec.parsePublish(MQTTPacket(header: qos1Header,
                                              body: Data([0x00, 0x01, 0x61, 0x12, 0x34]) + Data([7]))) {
    check(ok.packetID == 0x1234, "a QoS-1 publish yields its packet id")
    check(ok.payload == Data([7]), "…and the payload starts after it")
}

// An empty payload is legal — a retained-message clear is exactly this.
if let ok = MQTTCodec.parsePublish(MQTTPacket(header: 0x30, body: Data([0x00, 0x01, 0x61]))) {
    check(ok.payload.isEmpty, "an empty payload parses (a retained clear is one)")
}

// ── The short bodies ─────────────────────────────────────────────────────────

check(MQTTCodec.connackCode(MQTTPacket(header: 0x20, body: Data())) == nil, "an empty CONNACK is refused")
check(MQTTCodec.connackCode(MQTTPacket(header: 0x20, body: Data([0x00]))) == nil, "a one-byte CONNACK is refused")
check(MQTTCodec.connackCode(MQTTPacket(header: 0x20, body: Data([0x00, 0x05]))) == 5,
      "a CONNACK's return code is the SECOND byte, not the first")

check(MQTTCodec.pubackPacketID(Data()) == nil, "an empty PUBACK is refused")
check(MQTTCodec.pubackPacketID(Data([0x12])) == nil, "a one-byte PUBACK is refused")
check(MQTTCodec.pubackPacketID(Data([0x12, 0x34])) == 0x1234, "a PUBACK's id is big-endian")

// SUBACK is how an authorization refusal arrives. It is not an error and not
// silence, so reading this body is the difference between "the ACL has no row
// for this client" and an unexplained reconnect loop.
check(MQTTCodec.subackReturnCodes(Data([0x00, 0x01])) == nil, "a SUBACK with no return code is refused")
if let s = MQTTCodec.subackReturnCodes(Data([0x12, 0x34, 0x80])) {
    check(s.packetID == 0x1234, "the SUBACK names the subscribe it answers")
    check(s.codes == [0x80], "0x80 is a refusal, and it is readable")
}
if let s = MQTTCodec.subackReturnCodes(Data([0x00, 0x01, 0x00, 0x01, 0x80])) {
    check(s.codes.count == 3, "one code per topic, all of them")
    check(s.codes.contains(0x80), "a refusal among grants is still visible")
}

// ── Nothing off a socket may trap ────────────────────────────────────────────

var rng = SystemRandomNumberGenerator()
var fuzzed = 0
for _ in 0..<4000 {
    let n = Int.random(in: 0...300, using: &rng)
    var buf = Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &rng) })
    // Drain it the way `ingest` does, and make sure it terminates.
    var guardCount = 0
    loop: while guardCount < 64 {
        guardCount += 1
        switch MQTTCodec.nextPacket(from: &buf) {
        case .packet(let p):
            _ = MQTTCodec.parsePublish(p)
            _ = MQTTCodec.connackCode(p)
            _ = MQTTCodec.pubackPacketID(p.body)
            _ = MQTTCodec.subackReturnCodes(p.body)
        case .incomplete, .malformed:
            break loop
        }
    }
    check(guardCount < 64, "a random buffer drains rather than looping")
    fuzzed += 1
}
check(fuzzed == 4000, "\(fuzzed) random buffers parsed without trapping")

// A packet that parses must have consumed bytes — a `.packet` that consumed
// nothing is an infinite loop in every caller.
for _ in 0..<2000 {
    let n = Int.random(in: 2...80, using: &rng)
    var buf = Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &rng) })
    let before = buf.count
    if case .packet = MQTTCodec.nextPacket(from: &buf) {
        check(buf.count < before, "a parsed packet consumed its bytes")
    }
}

finish()
