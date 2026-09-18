import Foundation

/// ─── YOUR CODE GOES HERE ────────────────────────────────────────────────────
///
/// The target: what one fuzz input actually exercises.
///
/// The surface is `MQTTCodec` in Services/MQTTWireClient.swift — the decode half
/// of a hand-rolled MQTT 3.1.1 parser, fed by `ingest(_:)` straight from
/// `URLSessionWebSocketTask` with no authentication in front of it. Every byte
/// here is chosen by whoever is on the other end of the socket.
///
/// THE ORACLE IS "IT RETURNS". In C an out-of-bounds read is silent; in Swift it
/// TRAPS, and so does `Int` overflow and every force-unwrap of nil. So "the
/// process is still alive" is a real oracle on this target, and a crash here is
/// a remote DoS: one packet, every client that receives it dies, and it dies
/// again on reconnect.
func fuzzMQTTWire(_ input: Data) {
    // The parser is stateful across calls — `nextPacket` consumes from an
    // inout buffer and leaves the remainder for next time. So the harness must
    // model the ROLLING BUFFER, not a single packet, or the multi-packet and
    // partial-packet paths are never reached.
    var buffer = input

    loop: while true {
        // PROGRESS ORACLE. `nextPacket` is contracted to consume at least the
        // fixed header it just parsed. If some input makes it hand back a packet
        // without shrinking the buffer, this loop spins forever — and a hung
        // fuzzer reads exactly like a clean one from the outside.
        //
        // `precondition`, not `assert`: run.sh builds with -O, where `assert` is
        // compiled out and this oracle would silently stop existing.
        let before = buffer.count
        let packet: MQTTPacket
        switch MQTTCodec.nextPacket(from: &buffer) {
        case .packet(let p):
            packet = p
        case .incomplete:
            // RESOURCE ORACLE (was TODO(3), Rung M2). "Not yet" is only a legal
            // answer when the packet at the head of the buffer could still fit
            // inside the ceiling. `decodeLength` accepts a remaining length up to
            // 268,435,455 and `ingest` appends until the whole packet arrives, so
            // before the ceiling existed a five-byte header claiming 256 MB made
            // the client wait — and buffer — forever, with the ping timer
            // reporting a healthy link the entire time.
            //
            // So: whenever the head of the buffer holds a complete length prefix,
            // an `.incomplete` verdict must mean the claim is WITHIN the ceiling.
            // Anything else means an unbounded accumulation is being invited.
            if buffer.count >= 2,
               case .complete(let remaining, let lengthBytes) = MQTTCodec.decodeLength(buffer, from: 1) {
                precondition(1 + lengthBytes + remaining <= MQTTCodec.maxPacketBytes,
                             "incomplete on a packet claiming more than maxPacketBytes — unbounded buffering")
            }
            break loop
        case .malformed:
            // The connection dies here in `ingest`. Nothing further to decode,
            // and — the point of the third case — nothing further to buffer.
            break loop
        }
        precondition(buffer.count < before,
                     "nextPacket returned a packet without consuming input")
        precondition(before - buffer.count <= MQTTCodec.maxPacketBytes,
                     "a packet larger than maxPacketBytes was accepted")

        // Every decoder `handle(_:)` would reach for this packet type. The point
        // is not what they return — it is that returning happens at all.
        switch packet.type {
        case .publish: _ = MQTTCodec.parsePublish(packet)
        case .connack: _ = MQTTCodec.connackCode(packet)
        case .suback:  _ = MQTTCodec.subackReturnCodes(packet.body)
        case .puback:  _ = MQTTCodec.pubackPacketID(packet.body)
        default:       break
        }
    }

    // Rung M2 (resource bounds) is covered above, inside the loop: an
    // `.incomplete` verdict is only legal for a packet that could still fit
    // under `MQTTCodec.maxPacketBytes`, and no accepted packet may exceed it.
    // The client's answer to a 5-byte header claiming 256 MB is to fail the
    // connection — see `MQTTError.malformedStream`.
}

/// libFuzzer entry point, used only by `run.sh --libfuzzer`. Harmless when the
/// native driver is running — nothing calls it. Kept here so the target body is
/// written ONCE and both drivers share it.
@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    fuzzMQTTWire(Data(bytes: start, count: count))
    return 0
}
