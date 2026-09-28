import Foundation
import CryptoKit

/// The Swift half of the hqn/1 differential harness. Driven by
/// services/server/test/fuzz/noise-differential.ts.
///
/// WHY. The raw-TCP transport's handshake and framing are implemented twice —
/// services/server/lib/noise.ts for the gateway, Services/NoiseHQN.swift for the
/// app — and the pinned vectors only show they agree on VALID input. What an
/// attacker controls is the invalid input: a gateway (or anything on the path)
/// that sends a msg2 one implementation accepts and the other refuses is a
/// client that connects against one server build and not another, with
/// "decryption failed" as the only clue.
///
/// Usage:  noise-verdict <frames|msg2> <batch.jsonl> <noise-hqn-vectors.json>
///
///   frames  line = JSON array of base64 chunks, fed to a FrameReader in order
///           out:  F <n> <sha256 of the frames joined with their lengths> <pending>
///   msg2    line = base64 msg2, read by an initiator in vector case 0's state
///           out:  R                         refused
///                 A <payloadHex> <hhHex>    accepted

let args = CommandLine.arguments
guard args.count > 3, ["frames", "msg2"].contains(args[1]) else {
    FileHandle.standardError.write(Data("usage: noise-verdict <frames|msg2> <batch.jsonl> <vectors.json>\n".utf8))
    exit(2)
}
let mode = args[1]
let raw = (try? Data(contentsOf: URL(fileURLWithPath: args[2]))) ?? Data()

func hexOf(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func unhex(_ s: String) -> Data {
    var d = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        d.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return d
}

guard let vraw = FileManager.default.contents(atPath: args[3]),
      let V = try? JSONSerialization.jsonObject(with: vraw) as? [String: Any],
      let c = (V["cases"] as? [[String: Any]])?.first else {
    FileHandle.standardError.write(Data("could not read vectors\n".utf8))
    exit(2)
}
func field(_ k: String) -> Data { unhex(c[k] as? String ?? "") }

/// A fresh initiator in exactly the state vector case 0 leaves it in after msg1.
func initiatorAfterMsg1() -> NoiseHQN.Initiator {
    let server = NoiseHQN.ServerKeys(keyID: UInt8(c["keyId"] as? Int ?? 0),
                                     x25519: field("serverStaticPubHex"), hqc: field("serverHqcPublicHex"))
    let ct = field("kemCiphertextHex"), ss = field("kemSharedSecretHex")
    let i = try! NoiseHQN.Initiator(
        server: server,
        ephemeral: try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: field("clientEphemeralPrivHex")),
        encapsulate: { _ in (ct, ss) })
    _ = try! i.writeMessage1(payload: field("payload1Hex"))
    return i
}

var out = ""
for lineSub in String(decoding: raw, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true) {
    let line = Data(lineSub.utf8)
    switch mode {
    case "frames":
        guard let chunks = try? JSONSerialization.jsonObject(with: line) as? [String] else { out += "X\n"; continue }
        var reader = NoiseHQN.FrameReader()
        var joined = Data()
        var n = 0
        for b64 in chunks {
            reader.push(Data(base64Encoded: b64) ?? Data())
            while let f = reader.next() {
                n += 1
                joined.append(UInt8(f.count >> 8)); joined.append(UInt8(f.count & 0xFF))
                joined.append(f)
            }
        }
        out += "F \(n) \(hexOf(Data(SHA256.hash(data: joined)))) \(reader.pending)\n"
    default:
        guard let s = try? JSONSerialization.jsonObject(with: line, options: .fragmentsAllowed) as? String,
              let msg2 = Data(base64Encoded: s) else { out += "X\n"; continue }
        if let (payload, t) = try? initiatorAfterMsg1().readMessage2(msg2) {
            out += "A \(hexOf(payload)) \(hexOf(t.handshakeHash))\n"
        } else {
            out += "R\n"
        }
    }
}
FileHandle.standardOutput.write(Data(out.utf8))
