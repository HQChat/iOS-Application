import Foundation
import CryptoKit

/// The Swift half of the handshake differential harness.
///
/// WHY THIS FRAME. `h/{friendshipHash}` is what closes the impersonation gap an
/// `init` leaves open. An init is built entirely from public values and arrives
/// on an inbox every friend may publish to, so it proves nothing about who sent
/// it; the challenge/proof exchange on the handshake topic is the thing that
/// does. Both ends parse these frames with hand-written offset arithmetic, twice,
/// and a divergence means one peer accepts a frame the other refuses — which
/// here is not a dropped message but a stalled first contact, or worse, two
/// different opinions about who proved what.
///
/// THREE MODES, because the two halves fail differently:
///
///   decode  bytes in, frame out. Both must refuse the same bytes, and agree on
///           every field of what they accept.
///   encode  frame in, bytes out. Everything above tests decoders; the envelope
///           work found the ENCODERS disagreeing on every malformed input while
///           the decoders agreed, because they fail in structurally different
///           ways — TypeScript writes into a sized buffer, Swift appends.
///   round   decode(encode(f)) must return f. A decoder and an encoder can each
///           be self-consistent and still not be inverses.
///
/// Usage:  handshake-verdict <decode|encode|round> <batch.jsonl>
///
/// decode input:  one base64 string per line (the raw frame bytes).
/// encode input:  one JSON object per line: {kind, from, to, nonce, ct?, proof?}
///                with byte fields base64-encoded.
///
/// Output, one line per input line:
///
///   decode:  R                                   refused
///            A <kind> <from> <to> <nonceHex> <bodySha256> <bodyLen>
///   encode:  R                                   refused
///            A <sha256-of-frame-bytes> <len>
///   round:   R                                   encode refused (nothing to test)
///            T                                   round-tripped
///            F <why>                             did not

let args = CommandLine.arguments
guard args.count > 2, ["decode", "encode", "round"].contains(args[1]) else {
    FileHandle.standardError.write(Data("usage: handshake-verdict <decode|encode|round> <batch.jsonl>\n".utf8))
    exit(2)
}
let mode = args[1]
let raw = (try? Data(contentsOf: URL(fileURLWithPath: args[2]))) ?? Data()

func sha(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }
func hexOf(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

struct WireFrame: Decodable {
    let kind: String
    let from: String
    let to: String
    let nonce: String       // base64
    let ct: String?         // base64
    let proof: String?      // base64
}

func describe(_ f: Handshake.Frame) -> String {
    let kind = f.kind == .challenge ? "chal" : "proof"
    let body = f.ct ?? f.proof ?? Data()
    return "A \(kind) \(f.from) \(f.to) \(hexOf(f.nonce)) \(sha(body)) \(body.count)"
}

func frame(from w: WireFrame) -> Handshake.Frame? {
    guard let nonce = Data(base64Encoded: w.nonce) else { return nil }
    let ct = w.ct.flatMap { Data(base64Encoded: $0) }
    let proof = w.proof.flatMap { Data(base64Encoded: $0) }
    guard w.kind == "chal" || w.kind == "proof" else { return nil }
    return Handshake.Frame(kind: w.kind == "chal" ? .challenge : .proof,
                           from: w.from, to: w.to, nonce: nonce, ct: ct, proof: proof)
}

let decoder = JSONDecoder()
var out = Data()

for line in raw.split(separator: 0x0A, omittingEmptySubsequences: true) {
    switch mode {
    case "decode":
        // The line is a JSON string holding base64. Decoding to a String first
        // keeps the transport identical to the TypeScript side.
        guard let b64 = try? decoder.decode(String.self, from: Data(line)),
              let bytes = Data(base64Encoded: b64) else {
            out.append(Data("R\n".utf8)); continue
        }
        if let f = Handshake.decode(bytes) {
            out.append(Data((describe(f) + "\n").utf8))
        } else {
            out.append(Data("R\n".utf8))
        }

    case "encode":
        guard let w = try? decoder.decode(WireFrame.self, from: Data(line)),
              let f = frame(from: w), let bytes = Handshake.encode(f) else {
            out.append(Data("R\n".utf8)); continue
        }
        out.append(Data("A \(sha(bytes)) \(bytes.count)\n".utf8))

    default: // round
        guard let w = try? decoder.decode(WireFrame.self, from: Data(line)),
              let f = frame(from: w), let bytes = Handshake.encode(f) else {
            out.append(Data("R\n".utf8)); continue
        }
        guard let back = Handshake.decode(bytes) else {
            out.append(Data("F encode produced bytes its own decoder refuses\n".utf8)); continue
        }
        // Compared field by field rather than with ==, so a failure names the
        // field that moved instead of just saying the frames differ.
        var why: [String] = []
        if back.kind != f.kind { why.append("kind") }
        if back.from.lowercased() != f.from.lowercased() { why.append("from") }
        if back.to.lowercased() != f.to.lowercased() { why.append("to") }
        if back.nonce != f.nonce { why.append("nonce") }
        if f.kind == .challenge, back.ct != f.ct { why.append("ct") }
        if f.kind == .proof, back.proof != f.proof { why.append("proof") }
        out.append(Data((why.isEmpty ? "T\n" : "F \(why.joined(separator: ","))\n").utf8))
    }
}

FileHandle.standardOutput.write(out)
