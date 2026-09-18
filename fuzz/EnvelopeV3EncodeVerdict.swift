import Foundation

/// The ENCODE half of the v3 differential harness.
///
/// The decode harness proved the two parsers agree on the same bytes. It said
/// nothing about the encoders, and the encoders did not agree: given an
/// identical struct they produced different frames on every malformed input,
/// because they fail in structurally different ways. TypeScript builds a fixed
/// buffer and copies into it, so a short field silently leaves zeros and a long
/// one is clipped; this side APPENDS, so a wrong-length field shifts every field
/// after it. `writeUInt32BE` throws where `UInt32(truncatingIfNeeded:)` wraps.
///
/// So this reads STRUCTS rather than frames — one JSON object per line, binary
/// fields as hex — encodes each, and prints one verdict per line:
///
///     A <frameHex>   encoded
///     R              refused
///
/// The oracle is exact: both sides must refuse the same structs, and produce
/// byte-identical frames for the ones they accept.

guard CommandLine.arguments.count > 1 else {
    FileHandle.standardError.write(Data("usage: envelope-v3-encode-verdict <batch.jsonl>\n".utf8))
    exit(2)
}

func hexData(_ s: String) -> Data? {
    guard s.count % 2 == 0 else { return nil }
    var out = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
        out.append(b); i = j
    }
    return out
}
func hexString(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

let raw = (try? Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) ?? Data()
var out = Data()

for line in raw.split(separator: 0x0A, omittingEmptySubsequences: false) {
    guard !line.isEmpty,
          let obj = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else {
        out.append(Data("R\n".utf8))
        continue
    }
    // A field that is present but unreadable is a refusal, not a crash: the
    // point of this harness is that both sides say no to the same things.
    let blob: (String) -> Data? = { key in (obj[key] as? String).flatMap(hexData) }

    var frame = ConversationEnvelopeV3(
        t: (obj["t"] as? String) == "init" ? .initiate : .message,
        sender: (obj["sender"] as? String) ?? "",
        to: (obj["to"] as? String) ?? "",
        msgId: (obj["msgId"] as? String) ?? "",
        cid: (obj["cid"] as? String) ?? "",
        n: (obj["n"] as? Int) ?? -1,
        pn: (obj["pn"] as? Int) ?? -1,
        payload: blob("payload") ?? Data()
    )
    frame.rk = blob("rk")
    frame.kemCt = blob("kemCt")
    frame.ctId = blob("ctId")
    frame.ctMt = blob("ctMt")
    frame.ctOt = blob("ctOt")
    frame.senderPk = blob("senderPk")
    // Present-but-unrepresentable is NOT the same as absent, and conflating them
    // is a harness bug rather than an encoder one: `as? Int` quietly drops a
    // fractional value, so `otId: 1.5` became "no otId" here while TypeScript
    // kept it and refused. A sentinel that fails validation is what the other
    // numeric fields already do (`?? -1`), so this matches them.
    if obj.keys.contains("otId") {
        frame.otId = (obj["otId"] as? Int) ?? -1
    }

    if let encoded = frame.encoded() {
        out.append(Data("A \(hexString(encoded))\n".utf8))
    } else {
        out.append(Data("R\n".utf8))
    }
}

FileHandle.standardOutput.write(out)
