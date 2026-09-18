//
//  EnvelopeV3Tests.swift
//  DissQus tests
//
//  The v3 wire format, against the SAME vectors services/server asserts.
//
//  The property that matters most is one v2 could not have: the AAD is a PREFIX
//  of the frame. In v2 the canonical header is a second construction, written by
//  hand twice, beside a JSON encoding produced by two different libraries —
//  keeping those in step is unpaid work forever. Here there is one set of bytes
//  and the AAD is a range of it, so a receiver binds what it was actually sent.
//

import Foundation

guard CommandLine.arguments.count > 1 else {
    print("  ✗ no vector path given — run.sh must pass envelope-v3-vectors.json")
    exit(1)
}
guard let raw = FileManager.default.contents(atPath: CommandLine.arguments[1]),
      let V = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
      let cases = V["cases"] as? [String: Any] else {
    print("  ✗ could not read vectors at \(CommandLine.arguments[1])")
    exit(1)
}

check((V["version"] as? Int) == 3, "vector file is version 3")

let caseNames = ["msg", "stepping", "init", "initNoOneTime", "unicode"]

func vector(_ name: String) -> (frame: Data, aad: Data, fields: [String: Any])? {
    guard let c = cases[name] as? [String: Any],
          let frameHex = c["frameHex"] as? String,
          let aadHex = c["aadHex"] as? String,
          let fields = c["fields"] as? [String: Any],
          let frame = hexData(frameHex), let aad = hexData(aadHex)
    else { return nil }
    return (frame, aad, fields)
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

print("── every pinned frame decodes to the fields it claims ──")
for name in caseNames {
    guard let v = vector(name) else { check(false, "\(name): vector present"); continue }
    let got = ConversationEnvelopeV3.decodeReporting(v.frame)
    guard let frame = got.frame, let aad = got.aad else {
        check(false, "\(name) decodes (refused: \(got.rejection?.rawValue ?? "unknown"))")
        continue
    }
    var ok = frame.sender == v.fields["sender"] as? String
        && frame.to == v.fields["to"] as? String
        && frame.msgId == v.fields["msgId"] as? String
        && frame.cid == v.fields["cid"] as? String
        && frame.n == v.fields["n"] as? Int
        && frame.pn == v.fields["pn"] as? Int
    ok = ok && String(data: frame.payload, encoding: .utf8) == v.fields["payloadUtf8"] as? String
    if let wantOtId = v.fields["otId"] as? Int { ok = ok && frame.otId == wantOtId }
    check(ok, "\(name): every field survives the round trip")

    // THE property. The AAD is not rebuilt — it is a range of what arrived.
    check(aad == v.aad, "\(name): the decoder returns the pinned AAD")
    check(v.frame.prefix(aad.count) == aad, "\(name): the AAD is a PREFIX of the frame")

    // …and re-encoding is byte-stable, which is what makes the vectors a
    // contract rather than a snapshot.
    check(frame.encoded() == v.frame, "\(name): re-encodes to the same bytes")
    check(frame.canonicalHeader() == v.aad, "\(name): rebuilds the same header")
}

print("")
print("── the rules the format enforces, that v2 could only ask for ──")

guard let stepping = vector("stepping").flatMap({ ConversationEnvelopeV3.decode($0.frame) }),
      let initFrame = vector("init").flatMap({ ConversationEnvelopeV3.decode($0.frame) })
else {
    check(false, "the stepping and init vectors decode")
    finish()
}

// Refused by the ENCODER now, which is the stronger place for it: an encoder
// that can emit a frame its own decoder rejects is not much of a contract, and
// the two implementations used to fail that differently on every malformed
// input — this side by SHIFTING every field after a wrong-length one, the
// TypeScript side by padding or clipping in place.
var noKemCt = stepping
noKemCt.kemCt = nil
check(noKemCt.encoded() == nil, "a msg with rk and no kemCt produces no frame")

var noRk = stepping
noRk.rk = nil
check(noRk.encoded() == nil, "a msg with kemCt and no rk produces no frame")

// v2 could only TOLERATE the meaningless field, and the two implementations then
// disagreed about whether the pairing rule applied to an init — the bot omitted
// `kemCt`, the TypeScript parser demanded it, and every e2e conversation failed
// with the frame dropped at parse.
var initWithKemCt = initFrame
initWithKemCt.kemCt = Data(repeating: 7, count: 32)
check(initWithKemCt.encoded() == nil, "an init carrying a kemCt produces no frame")

var initNoRk = initFrame
initNoRk.rk = nil
check(initNoRk.encoded() == nil, "an init without rk produces no frame")

var substituted = initFrame
substituted.senderPk = Data(repeating: 0xab, count: initFrame.senderPk?.count ?? 7237)
check(substituted.encoded() == nil,
      "a senderPk that does not hash to sender produces no frame, on the way out too")

// ── The encoder's accept set ─────────────────────────────────────────────────
//
// It used to have none, and the two implementations then disagreed about every
// malformed input. The reachable case was an empty `peerID` — a contact an
// invite created before a directory sync filled it in — which on v2 produced a
// frame the receiver rejected and on v3 a well-formed one naming client 0000….
print("")
print("── the encoder refuses what it could not read back ──")

func mutating(_ change: (inout ConversationEnvelopeV3) -> Void) -> ConversationEnvelopeV3 {
    var f = stepping; change(&f); return f
}
let malformed: [(String, ConversationEnvelopeV3)] = [
    ("empty sender", ConversationEnvelopeV3(t: .message, sender: "", to: stepping.to,
        msgId: stepping.msgId, cid: stepping.cid, n: 0, pn: 0, payload: stepping.payload)),
    ("empty recipient", ConversationEnvelopeV3(t: .message, sender: stepping.sender, to: "",
        msgId: stepping.msgId, cid: stepping.cid, n: 0, pn: 0, payload: stepping.payload)),
    ("short sender", ConversationEnvelopeV3(t: .message, sender: String(repeating: "ab", count: 16),
        to: stepping.to, msgId: stepping.msgId, cid: stepping.cid, n: 0, pn: 0, payload: stepping.payload)),
    ("long sender", ConversationEnvelopeV3(t: .message, sender: String(repeating: "ab", count: 64),
        to: stepping.to, msgId: stepping.msgId, cid: stepping.cid, n: 0, pn: 0, payload: stepping.payload)),
    ("non-hex sender", ConversationEnvelopeV3(t: .message, sender: String(repeating: "z", count: 64),
        to: stepping.to, msgId: stepping.msgId, cid: stepping.cid, n: 0, pn: 0, payload: stepping.payload)),
    ("empty cid", ConversationEnvelopeV3(t: .message, sender: stepping.sender, to: stepping.to,
        msgId: stepping.msgId, cid: "", n: 0, pn: 0, payload: stepping.payload)),
    ("empty msgId", ConversationEnvelopeV3(t: .message, sender: stepping.sender, to: stepping.to,
        msgId: "", cid: stepping.cid, n: 0, pn: 0, payload: stepping.payload)),
    ("msgId over 128 bytes", ConversationEnvelopeV3(t: .message, sender: stepping.sender,
        to: stepping.to, msgId: String(repeating: "é", count: 65), cid: stepping.cid,
        n: 0, pn: 0, payload: stepping.payload)),
    ("negative n", mutating { $0.rk = nil; $0.kemCt = nil }),  // replaced below
]
var encoderRefusesAll = true
for (name, frame) in malformed.dropLast() where frame.encoded() != nil {
    print("  ✗ the encoder emitted a frame for: \(name)")
    encoderRefusesAll = false
}
// Counters, which is where the two languages diverged worst: writeUInt32BE
// throws where UInt32(truncatingIfNeeded:) silently wraps. Both refuse now.
for (name, value) in [("negative n", -1), ("n past u32", 1 << 32),
                      ("n at the old v2 ceiling", 9_007_199_254_740_991)] {
    let f = ConversationEnvelopeV3(t: .message, sender: stepping.sender, to: stepping.to,
                                   msgId: stepping.msgId, cid: stepping.cid, n: value, pn: 0,
                                   payload: stepping.payload)
    if f.encoded() != nil {
        print("  ✗ the encoder emitted a frame for: \(name)")
        encoderRefusesAll = false
    }
}
var emptyPayload = stepping
emptyPayload.payload = Data()
if emptyPayload.encoded() != nil {
    print("  ✗ the encoder emitted a frame with an empty payload")
    encoderRefusesAll = false
}
check(encoderRefusesAll, "every malformed struct produces no frame at all")
check(stepping.encoded() != nil, "…and the good case still encodes")

print("")
print("── the version and the recipient are inside the AAD ──")
if let v = vector("msg") {
    check(4 < v.aad.count, "the version byte is covered by the AAD")
    check(39 + 32 <= v.aad.count, "the recipient is covered by the AAD")

    var downgraded = v.frame
    downgraded[downgraded.startIndex + 4] = 2
    check(ConversationEnvelopeV3.decode(downgraded) == nil,
          "a downgraded version byte is not even parsed")

    var readdressed = v.frame
    readdressed[readdressed.startIndex + 39] ^= 0xff
    let got = ConversationEnvelopeV3.decodeReporting(readdressed)
    check(got.aad != nil && got.aad != v.aad,
          "re-addressing a frame changes the AAD, so the tag will not verify")
}

print("")
print("── hostile frames are refused, not crashed on ──")
if let v = vector("init") {
    func mutated(_ change: (inout Data) -> Void) -> Data {
        var d = v.frame; change(&d); return d
    }
    let hostile: [(String, Data)] = [
        ("empty", Data()),
        ("magic only", Data("HQCE".utf8)),
        ("truncated", v.frame.dropLast()),
        ("trailing byte", v.frame + Data([0])),
        ("bad magic", mutated { $0[$0.startIndex] = 0x58 }),
        ("unknown flag bit", mutated { $0[$0.startIndex + 6] = 0x80 }),
        ("unknown kind", mutated { $0[$0.startIndex + 5] = 9 }),
        ("msgId length 0", mutated { $0[$0.startIndex + 95] = 0 }),
        ("length prefix past the buffer", mutated {
            let at = $0.startIndex + 96 + 16
            $0[at] = 0x0f; $0[at + 1] = 0xff; $0[at + 2] = 0xff; $0[at + 3] = 0xff
        }),
    ]
    var allRefused = true
    for (name, bytes) in hostile where ConversationEnvelopeV3.decode(bytes) != nil {
        print("  ✗ accepted hostile input: \(name)")
        allRefused = false
    }
    check(allRefused, "every hostile frame is refused")
}

finish()
