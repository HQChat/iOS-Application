import Foundation
import CryptoKit

/// One half of the v3 differential harness: Swift's verdict on each frame.
///
/// Reads a file of one HEX-encoded frame per line and prints exactly one verdict
/// line per input line, in order:
///
///     A <aadLen>:<sha256-of-aad-hex>:<sha256-of-fields-hex>   accepted
///     R <reason>                                              refused
///
/// Hex rather than raw bytes because the frames are binary and a line-delimited
/// file of them would be ambiguous the moment a frame contained 0x0A — which,
/// with 57 kB of KEM material per init, it always does.
///
/// Three things must agree with the TypeScript driver, not two. Verdict, as
/// before. The AAD, as before — a divergence there surfaces as a GCM tag
/// mismatch, indistinguishable from a wrong key. And now the decoded FIELDS: v3
/// parses integers and offsets out of bytes rather than reading a JSON object,
/// so "both accepted, same AAD, different `n`" is a shape v2 could not produce
/// and this one can.
///
/// Reasons are NOT compared — the two sides name their refusals differently and
/// always will.

guard CommandLine.arguments.count > 1 else {
    FileHandle.standardError.write(Data("usage: envelope-v3-verdict <batch.hexlines>\n".utf8))
    exit(2)
}

func hexData(_ s: Substring) -> Data? {
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

/// A digest over every decoded field, so a disagreement about what the bytes
/// MEAN is caught and not only a disagreement about whether to accept them.
func fieldsDigest(_ f: ConversationEnvelopeV3) -> String {
    var h = SHA256()
    func put(_ s: String) { h.update(data: Data(s.utf8)); h.update(data: Data([0])) }
    put(f.t == .initiate ? "init" : "msg")
    put(f.sender); put(f.to); put(f.msgId); put(f.cid)
    put(String(f.n)); put(String(f.pn))
    put(f.otId.map(String.init) ?? "")
    for blob in [f.rk, f.kemCt, f.ctId, f.ctMt, f.ctOt, f.senderPk, f.payload] {
        put(blob.map { hexString($0) } ?? "")
    }
    return hexString(Data(h.finalize()))
}

let raw = (try? String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)) ?? ""
var out = Data()

// Empty lines are MEANINGFUL: a zero-length frame hex-encodes to the empty
// string, and it is a case worth having a verdict on. Dropping them would leave
// the two halves disagreeing about how many frames they were comparing.
for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
    guard let bytes = hexData(line) else {
        out.append(Data("R not hex\n".utf8))
        continue
    }
    let got = ConversationEnvelopeV3.decodeReporting(bytes)
    if let frame = got.frame, let aad = got.aad {
        let digest = hexString(Data(SHA256.hash(data: aad)))
        out.append(Data("A \(aad.count):\(digest):\(fieldsDigest(frame))\n".utf8))
    } else {
        out.append(Data("R \(got.rejection?.rawValue ?? "unknown")\n".utf8))
    }
}

FileHandle.standardOutput.write(out)
