//
//  ConversationEnvelopeV3.swift
//  DissQus
//
//  The v3 client↔client wire format: length-prefixed binary, with the canonical
//  header as the frame's own prefix. Mirrors services/server/lib/envelope-v3.ts
//  byte-for-byte; both sides assert the same envelope-v3-vectors.json.
//
//  ── Why a second format at all ──────────────────────────────────────────────
//  v2 is JSON carrying base64. That costs exactly the 33% you would expect, and
//  it lands on the frames that already hurt: roughly 24 kB of every 82 kB `init`
//  is encoding rather than protocol.
//
//  But the size was never the strongest argument. The AAD is the thing that has
//  to agree byte-for-byte between this client and the TypeScript bot, and in v2
//  it is a SECOND construction — a netstring encoding of a fixed field order,
//  written twice by hand, beside a JSON encoding produced by two different
//  libraries. Keeping those in step is unpaid work forever, and the ways they
//  drift are not obvious: the differential fuzzer's first run against v2 found
//  duplicate-key disagreement, unpaired surrogates, grapheme-vs-byte length
//  counting and wrong-typed optionals, none of which any test had caught.
//
//  Here the header IS the frame prefix. The AAD is a byte range of the thing
//  that arrived, so there is nothing to keep in step and no second encoding to
//  disagree about. That is the real reason for this file.
//
//  ── What is bound that was not ──────────────────────────────────────────────
//  `v` — the version is inside the header, so nobody can flip a client between
//  two formats without breaking the tag. In v2 it rode entirely outside the AAD,
//  inert only because no second version existed.
//
//  `to` — the recipient's client id. A v2 frame says who it is FROM and never
//  who it is for, which is why the client had to be taught to check the topic it
//  arrived on. This is the durable form of that check.
//
//  ── Layout ──────────────────────────────────────────────────────────────────
//  All integers big-endian. The header runs from byte 0 to the start of the
//  payload length, and that whole span is the AAD.
//
//    0   magic     4 bytes   "HQCE"
//    4   version   u8        3
//    5   kind      u8        0 = msg, 1 = init
//    6   flags     u8        bit0 rk, bit1 kemCt, bit2 one-time (ctOt+otId)
//    7   sender    32 bytes  the client id, RAW — v2 spent 64 characters on hex
//    39  to        32 bytes  the recipient's client id, raw
//    71  cid       16 bytes  the chain selector, raw — v2 spent 32 on hex
//    87  n         u32
//    91  pn        u32
//    95  msgIdLen  u8        1..128
//    96  msgId     msgIdLen bytes, UTF-8
//        [rk]      u32 len + rk
//        [kemCt]   u32 len + kemCt
//        [init]    u32 len + senderPk, u32 len + ctId, u32 len + ctMt
//        [oneTime] u32 len + ctOt, u32 otId
//    --- header ends here; everything above is the AAD ---
//        payload   u32 len + bytes
//

import Foundation

/// One frame on the wire.
///
/// The field names were chosen to match v2's so that the ratchet, the router and
/// the store never learned which version had delivered them — the difference
/// lived entirely in this file and its TypeScript twin. That worked: when v2 was
/// deleted, nothing above `ConversationFrame` changed at all.
///
/// Binary fields are `Data` rather than base64 strings — that is the whole point
/// — and the callers that need text (`sender`, `cid`) get hex, because that is
/// what `PeerID`, `DoubleRatchet.chainId` and every stored digest already use.
struct ConversationEnvelopeV3: Equatable {

    enum Kind: UInt8 {
        case message = 0   // everything after the handshake
        case initiate = 1  // opens a session; carries the handshake AND a message
    }

    let t: Kind
    /// Lowercase hex, 64 characters — decoded from the 32 raw bytes on the wire.
    let sender: String
    /// Lowercase hex, 64 characters. The field v2 has no equivalent of.
    let to: String
    let msgId: String
    /// Lowercase hex, 32 characters.
    let cid: String
    let n: Int
    let pn: Int

    var rk: Data?
    var kemCt: Data?
    var ctId: Data?
    var ctMt: Data?
    var ctOt: Data?
    var otId: Int?
    /// The initiator's full public key, RAW. v2 carried this as 14,474 hex
    /// characters for 7,237 bytes; `PeerID.matches` still hashes the hex TEXT,
    /// so the conversion happens on arrival rather than on the wire.
    var senderPk: Data?

    /// AES-GCM `[IV 12][tag 16][ct]`, raw.
    var payload: Data

    // MARK: - The format

    private static let magic = Data("HQCE".utf8)
    static let version: UInt8 = 3

    /// `rk` and `kemCt` get INDEPENDENT bits, which is the one place this format
    /// deliberately refuses to copy v2.
    ///
    /// A `msg` carries both or neither: a ratchet key with no ciphertext is not
    /// something a receiver can act on, and a ciphertext with no key names no
    /// chain. An `init` carries `rk` alone — it advertises the initiator's first
    /// chain, and there is no peer ratchet key to encapsulate against, so
    /// `kemCt` is meaningless on one. v2 could only express that by TOLERATING a
    /// field it never read, and the two implementations then disagreed about
    /// whether the pairing rule applied to an init: the bot omitted `kemCt`,
    /// the TypeScript parser demanded it, and every e2e conversation failed with
    /// the frame dropped at parse. Separate bits make the rule a property of the
    /// format instead of a convention.
    private static let flagRk: UInt8 = 0x01
    private static let flagKemCt: UInt8 = 0x02
    private static let flagOneTime: UInt8 = 0x04
    private static let allFlags: UInt8 = 0x07

    private static let offVersion = 4
    private static let offKind = 5
    private static let offFlags = 6
    private static let offSender = 7
    private static let offTo = 39
    private static let offCid = 71
    private static let offN = 87
    private static let offPn = 91
    private static let offMsgIdLen = 95
    private static let offMsgId = 96

    static let idBytes = 32
    static let cidBytes = 16
    static let maxMsgIdBytes = 128

    /// A bound that keeps a hostile length prefix from being read as an
    /// allocation request. Not a size policy — the transport has one of those.
    static let maxFieldBytes = 1 << 20

    /// Why a frame was refused. Every `return nil` names one, for the same
    /// reason v2's does: "decode returned nil" is not a diagnosis, and a frame
    /// that vanishes between the broker and the router looks identical whichever
    /// byte was wrong.
    enum Rejection: String {
        case notV3            = "not a v3 frame — wrong magic, version, or too short"
        case badKind          = "kind is neither msg nor init"
        case unknownFlags     = "a flag bit this build does not understand"
        case unpairedStep     = "a msg carries rk without kemCt, or the reverse"
        case initBadStep      = "an init must advertise rk and must not carry kemCt"
        case badMsgId         = "msgId is empty, over 128 bytes, or not valid UTF-8"
        case truncated        = "a length prefix runs past the end of the frame"
        case emptyField       = "a length-prefixed field is empty or implausibly large"
        case badCounter       = "n, pn or otId is negative or beyond a u32"
        case badChainId       = "cid is not 32 lowercase hex characters"
        case unpairedOneTime  = "ctOt and otId travel together or not at all"
        case trailingBytes    = "bytes after the payload"
        case badSender        = "sender or recipient is not a well-formed client id"
        case initKeyIdMismatch = "init senderPk does not hash to sender — REFUSED, possible substitution"
    }

    // MARK: - Writing

    private static func u32(_ value: Int) -> Data {
        let v = UInt32(truncatingIfNeeded: value)
        return Data([UInt8(truncatingIfNeeded: v >> 24), UInt8(truncatingIfNeeded: v >> 16),
                     UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)])
    }

    private static func blob(_ d: Data) -> Data { u32(d.count) + d }

    /// The largest counter this format carries. Four bytes, where v2 admitted any
    /// safe integer — so there were v2 frames with no v3 expression at all, and
    /// v2's own check was tightened to match rather than this being widened. The
    /// bound outlives the format that made it necessary.
    static let maxCounter = 0xffff_ffff

    /// Why an encoder validates at all.
    ///
    /// It used to validate nothing, and the two implementations then disagreed
    /// about every malformed input — because they fail in structurally
    /// different ways. TypeScript builds a fixed buffer and copies into it, so a
    /// short field silently leaves zeros and a long one is clipped. This side
    /// APPENDS, so a wrong-length field shifts every field after it and the
    /// frame comes out a different size. `writeUInt32BE` throws where
    /// `UInt32(truncatingIfNeeded:)` silently wraps.
    ///
    /// Same struct in, different bytes out — the exact class v3 exists to
    /// remove, in the half the differential fuzzer was not pointed at. So:
    /// refuse, rather than pad, shift, wrap or trap.
    ///
    /// The reachable case was not hypothetical. `sealMessage` reads `myID` and
    /// `friend.peerID` and guards neither, and both are empty in ordinary states
    /// — no profile loaded, or a contact an invite created before a directory
    /// sync filled it in.
    func validate() -> Rejection? {
        guard Self.isHex(sender, bytes: Self.idBytes) else { return .badSender }
        guard Self.isHex(to, bytes: Self.idBytes) else { return .badSender }
        guard Self.isHex(cid, bytes: Self.cidBytes) else { return .badChainId }
        guard Self.isCounter(n), Self.isCounter(pn) else { return .badCounter }

        let msgIdBytes = msgId.utf8.count
        guard msgIdBytes > 0, msgIdBytes <= Self.maxMsgIdBytes else { return .badMsgId }

        // Present-but-empty is refused for the same reason the decoder refuses
        // it: a zero-length blob is a field the sender believed in and the
        // receiver cannot use.
        for blob in [rk, kemCt, ctId, ctMt, ctOt, senderPk] {
            if let blob, blob.isEmpty || blob.count > Self.maxFieldBytes { return .emptyField }
        }
        if let otId, !Self.isCounter(otId) { return .badCounter }

        // The pairing rules, applied on the way OUT as well as the way in — an
        // encoder that can emit a frame its own decoder refuses is not much of a
        // contract.
        if t == .message, (rk == nil) != (kemCt == nil) { return .unpairedStep }
        if t == .initiate {
            guard rk != nil, kemCt == nil else { return .initBadStep }
            guard let senderPk, ctId != nil, ctMt != nil else { return .initBadStep }
            guard PeerID.matches(publicKeyHex: Self.hex(senderPk), id: sender) else {
                return .initKeyIdMismatch
            }
        }
        if (ctOt == nil) != (otId == nil) { return .unpairedOneTime }
        return nil
    }

    private static func isHex(_ value: String, bytes: Int) -> Bool {
        value.count == bytes * 2 && value.allSatisfy {
            ("0"..."9").contains($0) || ("a"..."f").contains($0)
        }
    }

    private static func isCounter(_ v: Int) -> Bool { v >= 0 && v <= maxCounter }

    /// The bytes both peers must bind as AAD, and the prefix of the frame itself.
    ///
    /// There is deliberately no separate "canonical encoding": `encoded()`
    /// returns this with a payload appended, and `decode` reports where it
    /// ended — so the AAD a receiver binds is what it received, not a rebuild.
    ///
    /// Nil when the fields cannot make a well-formed frame. See `validate`.
    func canonicalHeader() -> Data? {
        guard validate() == nil,
              let senderRaw = Self.unhex(sender),
              let toRaw = Self.unhex(to),
              let cidRaw = Self.unhex(cid)
        else { return nil }
        let msgIdBytes = Data(msgId.utf8)

        let hasOneTime = ctOt != nil && otId != nil
        var flags: UInt8 = 0
        if rk != nil { flags |= Self.flagRk }
        if kemCt != nil { flags |= Self.flagKemCt }
        if hasOneTime { flags |= Self.flagOneTime }

        var out = Data()
        out.reserveCapacity(Self.offMsgId + msgIdBytes.count)
        out += Self.magic
        out.append(Self.version)
        out.append(t.rawValue)
        out.append(flags)
        out += senderRaw
        out += toRaw
        out += cidRaw
        out += Self.u32(n)
        out += Self.u32(pn)
        out.append(UInt8(truncatingIfNeeded: msgIdBytes.count))
        out += msgIdBytes

        if let rk { out += Self.blob(rk) }
        if let kemCt { out += Self.blob(kemCt) }
        if t == .initiate, let senderPk, let ctId, let ctMt {
            out += Self.blob(senderPk)
            out += Self.blob(ctId)
            out += Self.blob(ctMt)
        }
        if hasOneTime, let ctOt, let otId {
            out += Self.blob(ctOt)
            out += Self.u32(otId)
        }
        return out
    }

    /// Header + payload. The complete frame, or nil when it would not be one.
    func encoded() -> Data? {
        guard !payload.isEmpty, payload.count <= Self.maxFieldBytes,
              let header = canonicalHeader() else { return nil }
        return header + Self.blob(payload)
    }

    // MARK: - Reading

    /// Whether these bytes even claim to be a v3 frame. Cheap, and total.
    static func looksLikeV3(_ raw: Data) -> Bool {
        raw.count >= offMsgId
            && raw.prefix(4) == magic
            && raw[raw.startIndex + offVersion] == version
    }

    static func decode(_ raw: Data) -> ConversationEnvelopeV3? {
        decodeReporting(raw).frame
    }

    /// `decode`, plus the reason when it refuses, plus the AAD as the exact byte
    /// range that arrived. A caller cannot get the AAD wrong by rebuilding it —
    /// which is the failure v2's parallel canonical encoding invites.
    static func decodeReporting(
        _ raw: Data
    ) -> (frame: ConversationEnvelopeV3?, aad: Data?, rejection: Rejection?) {
        guard looksLikeV3(raw) else { return (nil, nil, .notV3) }
        let base = raw.startIndex

        func u8(_ offset: Int) -> UInt8 { raw[base + offset] }
        func u32At(_ offset: Int) -> Int {
            (Int(raw[base + offset]) << 24) | (Int(raw[base + offset + 1]) << 16)
                | (Int(raw[base + offset + 2]) << 8) | Int(raw[base + offset + 3])
        }

        guard let t = Kind(rawValue: u8(offKind)) else { return (nil, nil, .badKind) }

        let flags = u8(offFlags)
        // Unknown bits are refused rather than ignored: a bit this build does not
        // understand changes what the sender thinks it sent, and the tag would
        // still verify because the flags byte is inside the AAD.
        guard flags & ~allFlags == 0 else { return (nil, nil, .unknownFlags) }
        let hasRk = flags & flagRk != 0
        let hasKemCt = flags & flagKemCt != 0
        let hasOneTime = flags & flagOneTime != 0

        // The pairing rule, as a property of the format rather than a convention.
        if t == .message, hasRk != hasKemCt { return (nil, nil, .unpairedStep) }
        if t == .initiate, !hasRk || hasKemCt { return (nil, nil, .initBadStep) }

        let msgIdLen = Int(u8(offMsgIdLen))
        guard msgIdLen > 0, msgIdLen <= maxMsgIdBytes else { return (nil, nil, .badMsgId) }
        var cursor = offMsgId + msgIdLen
        guard raw.count >= cursor else { return (nil, nil, .truncated) }

        let msgIdBytes = raw[(base + offMsgId)..<(base + cursor)]
        // Refused rather than replaced. Decoding invalid UTF-8 leniently would
        // substitute U+FFFD and silently change the bytes the AAD covers — the
        // same class as v2's unpaired surrogates, by a different door.
        guard let msgId = String(data: Data(msgIdBytes), encoding: .utf8),
              Data(msgId.utf8) == Data(msgIdBytes) else { return (nil, nil, .badMsgId) }

        /// Read a length-prefixed blob at the cursor, advancing it.
        func readBlob() -> Data?? {
            guard raw.count >= cursor + 4 else { return .some(nil) }
            let len = u32At(cursor)
            guard len <= maxFieldBytes else { return .some(nil) }
            cursor += 4
            guard raw.count >= cursor + len else { return .some(nil) }
            let out = Data(raw[(base + cursor)..<(base + cursor + len)])
            cursor += len
            return .some(out)
        }

        func next() -> Data? {
            guard let outer = readBlob(), let value = outer, !value.isEmpty else { return nil }
            return value
        }

        var rk: Data?
        if hasRk {
            guard let v = next() else { return (nil, nil, .truncated) }
            rk = v
        }
        var kemCt: Data?
        if hasKemCt {
            guard let v = next() else { return (nil, nil, .truncated) }
            kemCt = v
        }

        var senderPk: Data?, ctId: Data?, ctMt: Data?
        if t == .initiate {
            guard let a = next(), let b = next(), let c = next() else {
                return (nil, nil, .truncated)
            }
            senderPk = a; ctId = b; ctMt = c
        }

        var ctOt: Data?, otId: Int?
        if hasOneTime {
            guard let a = next() else { return (nil, nil, .truncated) }
            guard raw.count >= cursor + 4 else { return (nil, nil, .truncated) }
            ctOt = a
            otId = u32At(cursor)
            cursor += 4
        }

        // Everything up to here is the header, and the header is the AAD.
        let headerEnd = cursor
        guard let payload = next() else { return (nil, nil, .truncated) }
        // Trailing bytes are refused. A frame with something after the payload is
        // one two implementations could disagree about, and nothing legitimate
        // produces one.
        guard cursor == raw.count else { return (nil, nil, .trailingBytes) }

        let sender = hex(Data(raw[(base + offSender)..<(base + offSender + idBytes)]))
        let to = hex(Data(raw[(base + offTo)..<(base + offTo + idBytes)]))
        let cid = hex(Data(raw[(base + offCid)..<(base + offCid + cidBytes)]))
        guard PeerID.isWellFormed(sender), PeerID.isWellFormed(to) else {
            return (nil, nil, .badSender)
        }

        // An `init` must carry the key its `sender` id names. This is the check
        // that makes the id a commitment rather than a label, and the one place a
        // frame from an unknown peer introduces a key.
        if t == .initiate {
            guard let senderPk, PeerID.matches(publicKeyHex: hex(senderPk), id: sender) else {
                return (nil, nil, .initKeyIdMismatch)
            }
        }

        var frame = ConversationEnvelopeV3(
            t: t, sender: sender, to: to, msgId: msgId, cid: cid,
            n: u32At(offN), pn: u32At(offPn), payload: payload
        )
        frame.rk = rk
        frame.kemCt = kemCt
        frame.ctId = ctId
        frame.ctMt = ctMt
        frame.ctOt = ctOt
        frame.otId = otId
        frame.senderPk = senderPk
        return (frame, Data(raw[base..<(base + headerEnd)]), nil)
    }

    // MARK: - Hex

    // Scoped to this type rather than added to `Data`. `IdentityManager` already
    // extends `Data` with `hexString` / `init?(hexString:)`, and a second such
    // extension is a redeclaration — but this file also has to compile in the
    // cross-implementation test slice, without SwiftData, the Keychain or the
    // native HQC library behind it — which is also why the key length is spelled
    // out below rather than read from `HQCService`.

    private static func hex(_ d: Data) -> String {
        d.map { String(format: "%02x", $0) }.joined()
    }

    private static func unhex(_ text: String) -> Data? {
        guard text.count % 2 == 0 else { return nil }
        var out = Data(capacity: text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }
}
