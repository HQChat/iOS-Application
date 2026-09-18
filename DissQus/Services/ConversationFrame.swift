//
//  ConversationFrame.swift
//  DissQus
//
//  One frame — what the rest of the app calls a conversation message.
//  Mirrors services/server/lib/frame.ts.
//
//  ── WHAT THIS FILE USED TO BE ───────────────────────────────────────────────
//  A version seam. Two wire formats existed, v2 (JSON with base64 fields and a
//  second, parallel canonical encoding for the AAD) and v3 (length-prefixed
//  binary whose canonical header IS the frame's own prefix), and this file
//  confined the disagreement so that the ratchet, the router and the store saw
//  one shape. v2 is gone, so the disagreement is gone.
//
//  It survives as the NAME. `ConversationFrame` is what the app says;
//  `ConversationEnvelopeV3` is the CODEC that knows about magic bytes, offsets
//  and blob framing. Keeping those apart is what let v3 be added without the
//  ratchet ever learning it existed — and, in the end, let v2 be removed the
//  same way.
//
//  ── Why the AAD travels with the decode ─────────────────────────────────────
//  `decode` returns the AAD rather than offering a method to rebuild it: it is
//  the literal byte range that arrived — the header IS the frame prefix — so a
//  receiver binds what it was sent rather than a reconstruction. v2 had to
//  rebuild, and that asymmetry is exactly what v3 removed.
//
//  ── Sending ─────────────────────────────────────────────────────────────────
//  The payload is sealed AGAINST the header, so the header has to exist first:
//
//      let aad = fields.header()
//      let payload = try AESService.encryptRaw(text, key: k, aad: aad)
//      let bytes = fields.withPayload(payload).encoded()
//
//  `encoded()` re-derives the same header, so the two cannot drift.
//

import Foundation

/// A frame. Every binary field is `Data`, never base64 — which was the whole
/// point of the format change: v2 spelled them as base64 inside JSON, so every
/// frame paid for a conversion in each direction.
struct ConversationFrame: Equatable {

    enum Kind: Equatable {
        case initiate
        case message
    }

    var t: Kind
    /// The sender's client id, lowercase hex.
    var sender: String
    /// The recipient's client id, lowercase hex, and bound as AAD.
    ///
    /// It was optional while v2 existed, because a v2 frame said who it was from
    /// and never who it was for — which is why a v2 receiver had to fall back on
    /// checking which TOPIC a frame arrived on. Binding the recipient is the
    /// single reason the wire format was worth changing.
    var to: String
    var msgId: String
    /// Chain selector, lowercase hex.
    var cid: String
    var n: Int
    var pn: Int

    var rk: Data?
    var kemCt: Data?
    var ctId: Data?
    var ctMt: Data?
    var ctOt: Data?
    var otId: Int?
    /// The initiator's full public key, raw bytes.
    var senderPk: Data?

    /// AES-GCM `[IV 12][tag 16][ct]`, raw.
    var payload: Data

    // MARK: - Writing

    /// The bytes to bind as AAD for a frame being SENT.
    ///
    /// `payload` is ignored here on purpose: it is the thing being
    /// authenticated, and it does not exist yet when this is called.
    /// Nil when these fields cannot make a well-formed frame — see `validate`.
    func header() -> Data? {
        guard validate() == nil else { return nil }
        return asV3().canonicalHeader()
    }

    /// Why a frame is checked on the way OUT.
    ///
    /// The v3 encoders used to validate nothing and disagreed on every malformed
    /// input, because they fail in structurally different ways. The reachable
    /// case is ordinary: `sealMessage` reads `myID` and `friend.peerID` and
    /// guards neither, and both are empty in ordinary states.
    ///
    /// This had a second, hand-written copy of the rules for v2 frames. That
    /// copy is what went with v2 — there is one accept set now, in
    /// `ConversationEnvelopeV3`, and it cannot drift from itself.
    func validate() -> String? {
        asV3().validate()?.rawValue
    }

    /// The complete frame ready to publish, or nil when it would not be one.
    func encoded() -> Data? {
        guard validate() == nil, !payload.isEmpty else { return nil }
        return asV3().encoded()
    }

    func withPayload(_ payload: Data) -> ConversationFrame {
        var copy = self
        copy.payload = payload
        return copy
    }

    // MARK: - Reading

    /// Decode a frame, with the AAD it must be opened against.
    ///
    /// There is nothing to discriminate. A frame begins with a magic and a
    /// version byte, both inside the AAD, and anything that fails there is not a
    /// frame — not "might be the older format". While v2 existed, that fallback
    /// was the thing an attacker used to avoid the recipient binding: send v2,
    /// and both receivers took it.
    static func decode(_ raw: Data) -> (frame: ConversationFrame, aad: Data, rejection: String?)? {
        let got = ConversationEnvelopeV3.decodeReporting(raw)
        guard let env = got.frame, let aad = got.aad else { return nil }
        return (ConversationFrame(env), aad, nil)
    }

    /// `decode`, and the reason when it refuses — a dropped frame with no
    /// explanation is how a broken handshake stays invisible.
    static func decodeReporting(_ raw: Data) -> (result: (frame: ConversationFrame, aad: Data)?, reason: String) {
        let got = ConversationEnvelopeV3.decodeReporting(raw)
        guard let env = got.frame, let aad = got.aad else {
            return (nil, got.rejection?.rawValue ?? "unknown")
        }
        return ((ConversationFrame(env), aad), "")
    }

    // MARK: - The codec

    private init(_ e: ConversationEnvelopeV3) {
        t = e.t == .initiate ? .initiate : .message
        sender = e.sender
        to = e.to
        msgId = e.msgId
        cid = e.cid
        n = e.n
        pn = e.pn
        rk = e.rk
        kemCt = e.kemCt
        ctId = e.ctId
        ctMt = e.ctMt
        ctOt = e.ctOt
        otId = e.otId
        senderPk = e.senderPk
        payload = e.payload
    }

    init(t: Kind, sender: String, to: String, msgId: String, cid: String,
         n: Int, pn: Int, rk: Data? = nil, kemCt: Data? = nil, ctId: Data? = nil,
         ctMt: Data? = nil, ctOt: Data? = nil, otId: Int? = nil, senderPk: Data? = nil,
         payload: Data = Data()) {
        self.t = t; self.sender = sender; self.to = to
        self.msgId = msgId; self.cid = cid; self.n = n; self.pn = pn
        self.rk = rk; self.kemCt = kemCt; self.ctId = ctId; self.ctMt = ctMt
        self.ctOt = ctOt; self.otId = otId; self.senderPk = senderPk
        self.payload = payload
    }

    private func asV3() -> ConversationEnvelopeV3 {
        var out = ConversationEnvelopeV3(
            t: t == .initiate ? .initiate : .message,
            sender: sender,
            to: to,
            msgId: msgId,
            cid: cid,
            n: n,
            pn: pn,
            payload: payload
        )
        out.rk = rk
        out.kemCt = kemCt
        out.ctId = ctId
        out.ctMt = ctMt
        out.ctOt = ctOt
        out.otId = otId
        out.senderPk = senderPk
        return out
    }

    // `hex` and `unhex` stood here. They existed because v2 carried the
    // initiator's public key as 14,474 HEX CHARACTERS for 7,237 bytes, so every
    // frame paid for a conversion in each direction. v3 carries the raw bytes
    // and converts on arrival only where `PeerID.matches` needs the hex TEXT to
    // hash — which is once, at first contact, rather than once per init.
}
