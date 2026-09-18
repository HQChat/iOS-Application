// The frame seam — the one thing on this client that reads bytes a stranger sent.
//
// 283 lines, and until now no unit slice compiled them. `e2e/run.sh` and
// `fuzz/run.sh` do exercise this file, but neither is instrumented, so it read
// as zero and, more to the point, nothing asserted its REFUSALS in isolation.
//
// Everything below is about one property: a frame that arrives is untrusted
// until this file says otherwise, and the two ways that goes wrong are opposite.
// Accept too much and a peer can spell a frame that opens against the wrong AAD
// or names a sender it does not hold. Accept too little and a legitimate build
// silently stops being able to talk — with a dropped frame and no explanation,
// which is how a broken handshake stays invisible.
//
// ⚠️ This file used to run most of its script TWICE, once per wire version, and
// the loop was the point: the seam's claim was that the version is only a
// spelling. The claim held — nothing above `ConversationFrame` changed when v2
// was deleted — and there is one spelling now. Where a test only made sense as a
// comparison between two formats, it has been rewritten to assert the property
// that comparison was protecting, rather than dropped.

import Foundation

// ── Fixtures, built the way ChatSession and e2e/Party build them ─────────────

// An init's `senderPk` must HASH TO its `sender`, and the decoder enforces it:
// "init senderPk does not hash to sender — REFUSED, possible substitution". That
// commitment is what lets the bot encapsulate to a key taken from the frame
// itself. So the sender here is DERIVED from the key rather than picked, which
// my first fixture got wrong — it paired an arbitrary id with arbitrary bytes
// and the init was refused, correctly.
let SENDER_PK = Data(repeating: 7, count: 64)
let SENDER = PeerID.from(publicKeyHex: SENDER_PK.map { String(format: "%02x", $0) }.joined())
let RECIP  = String(repeating: "b2", count: 32)
let CID    = String(repeating: "c3", count: 16)   // 32 hex = a chain selector

func message(payload: Data = Data([1, 2, 3])) -> ConversationFrame {
    ConversationFrame(
        t: .message, sender: SENDER, to: RECIP,
        msgId: "m-1", cid: CID, n: 1, pn: 0,
        rk: Data(repeating: 9, count: 32), kemCt: Data(repeating: 8, count: 64),
        payload: payload)
}

func initiate() -> ConversationFrame {
    ConversationFrame(
        t: .initiate, sender: SENDER, to: RECIP,
        msgId: "i-1", cid: CID, n: 0, pn: 0,
        rk: Data(repeating: 9, count: 32),
        ctId: Data(repeating: 1, count: 32), ctMt: Data(repeating: 2, count: 32),
        senderPk: SENDER_PK,
        payload: Data([4, 5, 6]))
}

// ── What a valid frame is ────────────────────────────────────────────────────

check(message().validate() == nil, "a well-formed message validates")
check(initiate().validate() == nil, "a well-formed init validates")
check(message().encoded() != nil, "…and encodes")

// A frame must name its recipient. `to` is a non-optional `String` now — under
// v2 it was optional, because a v2 frame said who it was FROM and never who it
// was FOR, which is why a v2 receiver had to fall back on checking which topic
// the frame arrived on. That gap is the whole reason the format changed. The
// empty string is the closest a caller can still get to omitting it, and it
// cannot be a client id.
var noTo = message(); noTo.to = ""
check(noTo.validate() != nil, "a frame with no recipient is refused")
check(noTo.encoded() == nil, "…and cannot be spelled")

// ── The refusals ─────────────────────────────────────────────────────────────

func refuses(_ label: String, _ mutate: (inout ConversationFrame) -> Void) {
    var f = message()
    mutate(&f)
    check(f.validate() != nil, "refused: \(label)")
    check(f.encoded() == nil, "refused: \(label) — and produces no bytes")
}

refuses("sender is not 64 hex")            { $0.sender = "short" }
refuses("sender has uppercase hex")        { $0.sender = String(repeating: "A1", count: 32) }
refuses("sender is 63 characters")         { $0.sender = String(repeating: "a", count: 63) }
refuses("sender is not hex at all")        { $0.sender = String(repeating: "z", count: 64) }
refuses("recipient is not 64 hex")         { $0.to = "short" }
refuses("cid is not 32 hex")               { $0.cid = "deadbeef" }
refuses("n is negative")                   { $0.n = -1 }
refuses("pn is negative")                  { $0.pn = -1 }
refuses("n is past a u32")                 { $0.n = ConversationEnvelopeV3.maxCounter + 1 }
refuses("pn is past a u32")                { $0.pn = ConversationEnvelopeV3.maxCounter + 1 }
refuses("msgId is empty")                  { $0.msgId = "" }
refuses("msgId is over 128 bytes")         { $0.msgId = String(repeating: "x", count: 129) }

// The one-time prekey pair. `ctOt` is set alongside on purpose: without it the
// frame is refused for the PAIRING rule ("ctOt and otId travel together"), and
// the test would pass while asserting nothing about the counter bound it names.
refuses("otId is negative")                { $0.ctOt = Data(repeating: 4, count: 32); $0.otId = -1 }
refuses("otId is past a u32")              { $0.ctOt = Data(repeating: 4, count: 32)
                                             $0.otId = ConversationEnvelopeV3.maxCounter + 1 }
refuses("ctOt arrives without its otId")   { $0.ctOt = Data(repeating: 4, count: 32) }

// The ratchet pair. A message advertising a new ratchet key without the
// ciphertext that establishes it — or the reverse — is a step the receiver
// cannot complete, and taking it half-way desynchronises the chain.
refuses("a msg carries rk without kemCt")  { $0.kemCt = nil }
refuses("a msg carries kemCt without rk")  { $0.rk = nil }

// An init with no advertised key, or no key to check the sender against.
var initNoRk = initiate(); initNoRk.rk = nil
check(initNoRk.validate() != nil, "refused: an init with no rk")
var initNoPk = initiate(); initNoPk.senderPk = nil
check(initNoPk.validate() != nil, "refused: an init with no senderPk")

// An init carrying a `kemCt` — which v2 TOLERATED and this format refuses. An
// init has no peer ratchet key to encapsulate against, so the field is
// meaningless on one; v2 let it ride along, and the old cross-implementation
// vector actually had one, which is why nothing ever noticed.
var initWithKemCt = initiate(); initWithKemCt.kemCt = Data(repeating: 6, count: 64)
check(initWithKemCt.validate() != nil, "refused: an init carrying a kemCt")

// A msgId is bounded in BYTES, not characters: 128 emoji is 512 bytes, and a
// length check on `.count` would let it through.
var wideId = message(); wideId.msgId = String(repeating: "🔒", count: 40)
check(wideId.msgId.count == 40 && wideId.msgId.utf8.count > 128,
      "the fixture is wide but short in characters")
check(wideId.validate() != nil, "refused: a msgId bounded by characters rather than bytes")

// ── The key commitment ───────────────────────────────────────────────────────
//
// An init carries the sender's public key, and the receiver encapsulates a
// challenge to it. That is only safe because the key is COMMITTED: an init whose
// senderPk does not hash to the sender it names is refused. Without it, a peer
// could publish an init naming somebody else's id and carrying its own key, and
// the challenge would go to the impostor.
var impostor = initiate()
impostor.sender = String(repeating: "ff", count: 32)   // a real id, the wrong one
check(impostor.validate() != nil, "an init whose senderPk does not hash to its sender is refused")
check(impostor.encoded() == nil, "…and cannot be spelled at all")

// The same substitution, attempted from the wire rather than from the struct:
// take a valid init and rewrite the key it carries.
if let good = initiate().encoded() {
    var swapped = good
    if let range = swapped.range(of: SENDER_PK) {
        swapped.replaceSubrange(range, with: Data(repeating: 0x5A, count: SENDER_PK.count))
        let got = ConversationFrame.decodeReporting(swapped)
        check(got.result == nil, "a substituted senderPk is refused at decode")
        check(got.reason.lowercased().contains("sender") || got.reason.contains("init"),
              "…and the reason names it: \(got.reason)")
    } else {
        check(false, "the fixture key was not found in the encoded frame")
    }
}

// ── The seam refuses to spell what it could not read back ────────────────────

var empty = message(); empty.payload = Data()
check(empty.encoded() == nil,
      "an empty payload produces no frame — the bot logs \"refusing to publish a malformed frame\" on this")

// ── Round trip ───────────────────────────────────────────────────────────────

if let bytes = message().encoded(), let out = ConversationFrame.decode(bytes) {
    let back = out.frame
    check(back.sender == SENDER, "the sender survives")
    check(back.to == RECIP, "the recipient survives")
    check(back.cid == CID, "the chain selector survives")
    check(back.n == 1 && back.pn == 0, "the counters survive")
    check(back.payload == Data([1, 2, 3]), "the payload survives byte for byte")
    check(back.rk == Data(repeating: 9, count: 32), "the ratchet key survives")
    check(!out.aad.isEmpty, "decode yields an AAD to open against")

    // The AAD is the frame's own PREFIX, not a rebuild. v2 carried a second,
    // parallel canonical encoding, and a receiver binding a reconstruction can
    // bind something other than what arrived — which surfaces as a GCM tag
    // mismatch, indistinguishable from a wrong key.
    check(bytes.prefix(out.aad.count) == out.aad, "the AAD is the bytes that arrived")

    // …and the recipient is INSIDE it, which is the only thing that makes the
    // field worth carrying. Re-aiming a frame changes what the receiver binds,
    // so a republished frame does not open — rather than merely failing a topic
    // check a receiver might forget to make.
    var elsewhere = message(); elsewhere.to = String(repeating: "a7", count: 32)
    if let other = elsewhere.encoded(), let otherOut = ConversationFrame.decode(other) {
        check(otherOut.aad != out.aad, "changing the recipient changes the AAD")
    } else {
        check(false, "the re-aimed fixture did not encode")
    }
} else {
    check(false, "a valid message did not round-trip")
}

// An init's key material, which is what first contact is made of.
if let b = initiate().encoded(), let out = ConversationFrame.decode(b) {
    check(out.frame.t == .initiate, "an init decodes as an init")
    check(out.frame.ctId == Data(repeating: 1, count: 32), "ctId survives")
    check(out.frame.ctMt == Data(repeating: 2, count: 32), "ctMt survives")
    check(out.frame.senderPk == SENDER_PK, "senderPk survives")
}

// ── Anything that is not a well-formed frame is refused ──────────────────────
//
// ⚠️ Two DOWNGRADE tests stood here and they were the sharpest in the file: a v2
// frame claiming v3 in a field was not promoted to the v3 parser, and a v3 frame
// with a forged discriminator was refused rather than re-parsed as v2. Both are
// trivially true with one parser — there is nowhere to be promoted to or demoted
// into — so keeping them as written would be coverage that reads as coverage and
// tests nothing.
//
// What replaces them is the property they were protecting, stated for one
// format. Every case below either WAS a legal frame, or was the shape an
// attacker used to reach the weaker parser.
if let bytes = message().encoded() {
    check(ConversationEnvelopeV3.looksLikeV3(bytes), "a real frame is recognised")

    // A well-formed v2 frame. This used to decode, and decoding it was the
    // downgrade: an attacker avoiding the recipient binding simply sent one.
    let v2ish = Data(#"{"v":2,"t":"msg","sender":"\#(SENDER)","msgId":"m-1","cid":"\#(CID)"}"#.utf8)
    check(!ConversationEnvelopeV3.looksLikeV3(v2ish), "JSON is not a frame")
    check(ConversationFrame.decodeReporting(v2ish).result == nil,
          "a well-formed v2 frame is refused, not handed to a fallback parser")

    // The magic is half the discriminator and it is inside the AAD, so
    // corrupting it cannot move a frame anywhere — there is nowhere to move it.
    var forgedMagic = bytes
    forgedMagic[forgedMagic.startIndex] = 0x7B   // '{', so it looks like JSON
    check(ConversationFrame.decodeReporting(forgedMagic).result == nil,
          "a frame with a forged magic is refused")

    // The version byte is the other half. A frame claiming to be the older
    // format is refused rather than routed to it.
    var forgedVersion = bytes
    forgedVersion[forgedVersion.index(forgedVersion.startIndex, offsetBy: 4)] = 2
    check(ConversationFrame.decodeReporting(forgedVersion).result == nil,
          "a frame claiming version 2 in its version byte is refused")
}

// ── A refusal has to say why ─────────────────────────────────────────────────

for (label, bytes) in [
    ("empty", Data()),
    ("one byte", Data([0x00])),
    ("not json", Data("hello".utf8)),
    ("empty json", Data("{}".utf8)),
    ("json array", Data("[]".utf8)),
    ("truncated frame", (message().encoded() ?? Data()).prefix(8)),
] {
    let got = ConversationFrame.decodeReporting(Data(bytes))
    check(got.result == nil, "\(label) is refused")
    check(!got.reason.isEmpty,
          "\(label): a dropped frame with no explanation is how a broken handshake stays invisible")
}

check(ConversationFrame.decodeReporting(message().encoded()!).reason.isEmpty,
      "a frame that decodes carries no rejection reason")

// ── Nothing a stranger can send may trap ─────────────────────────────────────

// Not a fuzzer — fuzz/run.sh has those — but the shapes a parser dies on most
// often, run through both entry points.
var rng = SystemRandomNumberGenerator()
var cases: [Data] = []
if let good = message().encoded() {
    for cut in [0, 1, 2, 3, 7, 15, 31, good.count / 2, good.count - 1] where cut <= good.count {
        cases.append(Data(good.prefix(cut)))
    }
    for i in stride(from: 0, to: min(good.count, 64), by: 7) {
        var flipped = good
        flipped[flipped.startIndex + i] ^= 0xFF
        cases.append(flipped)
    }
    cases.append(good + Data(repeating: 0, count: 1024))   // trailing garbage
}
for n in [0, 1, 2, 3, 16, 1024, 65536] {
    cases.append(Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &rng) }))
}
cases.append(Data(repeating: 0x7B, count: 4096))            // 4 kB of '{'
cases.append(Data(String(repeating: "{\"v\":2,", count: 512).utf8))

var decoded = 0
for c in cases {
    let a = ConversationFrame.decode(c)             // must not trap
    let b = ConversationFrame.decodeReporting(c)    // must not trap
    if a != nil { decoded += 1 }
    // The two entry points must agree about whether this is a frame at all.
    check((a == nil) == (b.result == nil),
          "decode and decodeReporting agree on \(c.count) bytes")
}
check(true, "\(cases.count) malformed inputs parsed without trapping (\(decoded) decoded)")

// Anything that DOES decode must be internally consistent — a parser that
// returns a frame it would not itself accept hands the ratchet a shape the
// sender never validated.
for c in cases {
    if let got = ConversationFrame.decode(c) {
        check(got.frame.validate() == nil || got.rejection != nil,
              "a decoded frame either validates or is reported as rejected")
    }
}

finish()
