import Foundation
import CryptoKit

/// One half of the scrubber differential harness: Swift's redaction of each input.
///
/// WHY THIS TARGET EXISTS. `Redaction.swift` and `services/server/lib/scrub.ts`
/// are one rule set maintained twice, and each file carries a comment telling
/// the next person to keep them in step. Nothing enforced that. A divergence is
/// not cosmetic: it means a shape redacted on one platform ships in the clear
/// from the other, and for a messenger whose server never sees plaintext, the
/// client is the side that has the plaintext.
///
/// Two modes, because both halves of the scrubber can drift independently and a
/// combined oracle would not say which drifted:
///
///     redact   the textual redactors — regex order, placeholders, truncation
///     key      isSensitive(key) — the word-splitting that decides whether a
///              value is dropped regardless of what it looks like
///
/// Usage:  scrub-verdict <redact|key> <batch.jsonl>
///
/// Input is JSONL where each line is a JSON *string* literal, so newlines, quotes
/// and escapes all survive transport and both sides decode the same scalars. A
/// line Swift cannot decode prints `X` and the driver skips it — that is a
/// property of JSON, not of the scrubber, and counting it as a mismatch would
/// bury real findings under transport noise.
///
/// Output, one line per input line, in order:
///
///     redact:  R <sha256-of-output-hex> <byteLen> <base64-of-first-120-bytes>
///     key:     K <S|->
///     either:  X                        (this line could not be decoded)
///
/// The digest is the oracle; the base64 prefix is so a mismatch report is
/// readable without re-running. Hashing rather than shipping the whole output
/// keeps a 2000-line batch to kilobytes when inputs run to the 8 kB cap.

let args = CommandLine.arguments
guard args.count > 2, args[1] == "redact" || args[1] == "key" else {
    FileHandle.standardError.write(Data("usage: scrub-verdict <redact|key> <batch.jsonl>\n".utf8))
    exit(2)
}
let mode = args[1]
let raw = (try? Data(contentsOf: URL(fileURLWithPath: args[2]))) ?? Data()
let decoder = JSONDecoder()
var out = Data()

for line in raw.split(separator: 0x0A, omittingEmptySubsequences: true) {
    guard let input = try? decoder.decode(String.self, from: Data(line)) else {
        out.append(Data("X\n".utf8))
        continue
    }

    if mode == "key" {
        out.append(Data("K \(Redaction.isSensitive(input) ? "S" : "-")\n".utf8))
        continue
    }

    let redacted = Redaction.redact(input) ?? ""
    let bytes = Data(redacted.utf8)
    let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    let preview = bytes.prefix(120).base64EncodedString()
    out.append(Data("R \(digest) \(bytes.count) \(preview)\n".utf8))
}

FileHandle.standardOutput.write(out)
