//
//  Handshake.swift
//  DissQus
//
//  Proof that an `init` came from the peer it names. Mirrors
//  services/server/lib/handshake.ts; both sides assert handshake-vectors.json.
//
//  ── The hole this closes ────────────────────────────────────────────────────
//  `startAsInitiator` encapsulates three times, and every one of them is to the
//  RESPONDER's keys. The initiator's own identity secret never enters the
//  derivation. So an `init` is built entirely from public values — the
//  responder's prekey bundle is published for anyone to claim, and `senderPk` is
//  fetchable without a session at all — and any accepted friend can produce one
//  that names a third party and authenticates perfectly.
//
//  The docstring on `startAsInitiator` explains the first encapsulation as
//  authenticating the peer. That is the right sentence pointed the wrong way:
//  encapsulating to the responder's identity key means only the RESPONDER can
//  decapsulate, which authenticates the responder to the initiator. Nothing ever
//  authenticated the initiator.
//
//  ── Why a round trip, and why an HQC one ────────────────────────────────────
//  A KEM cannot authenticate a sender in one flight. Encapsulation demonstrates
//  the RECIPIENT's secret, never the sender's, so proving the initiator holds a
//  secret means the initiator must receive something first. X3DH gets this from
//  DH(IK_A, SPK_B), which needs the initiator's secret; PQXDH keeps those DHs
//  for exactly this reason and adds a KEM only for forward secrecy.
//
//  This is HQC research, so it takes the round trip rather than a second
//  primitive: the challenge is an ordinary HQC encapsulation to the initiator's
//  IDENTITY key, and the proof is HKDF over the shared secret — the same
//  construction the MQTT auth handshake already uses, with a different `info` so
//  the two can never be confused.
//
//  ── What the proof binds ────────────────────────────────────────────────────
//      info  = "hqchat/handshake/v1" ‖ nonce(32) ‖ challenger(32) ‖ prover(32)
//      proof = HKDF-SHA256(ikm: ss, salt: "salt", info, 32)
//
//  The nonce is freshness; the two ids are bound IN ORDER, so a proof made for
//  one pair cannot be presented to another and cannot be reflected back at its
//  own author. Every component is fixed-width — no delimiters to confuse, and
//  no encoding for the two implementations to disagree about.
//
//  ── What it does not defend against ─────────────────────────────────────────
//  A relay. Somebody who can both see the challenge and reach the real peer
//  could forward it. What stops that here is the transport: the exchange runs on
//  `h/{friendshipHash}`, which only the two members are granted, so a friend of
//  ours with no grant on it never sees the challenge. A malicious broker still
//  can, and is outside what any of this defends — it writes the ACL.
//

import Foundation
import CryptoKit

enum Handshake {

    /// Bytes of freshness in a challenge.
    static let nonceBytes = 32
    /// Bytes of proof. Same width as the MQTT auth proof, for the same reason.
    static let proofBytes = 32

    private static let infoPrefix = Data("hqchat/handshake/v1".utf8)
    private static let salt = Data("salt".utf8)
    private static let idBytes = 32

    /// A fresh challenge nonce.
    static func nonce() -> Data {
        var out = Data(count: nonceBytes)
        _ = out.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, nonceBytes, $0.baseAddress!) }
        return out
    }

    /// The proof a prover returns for one challenge.
    ///
    /// `challenger` and `prover` are client ids in lowercase hex — the same 64
    /// characters the wire carries — bound in that order.
    static func proof(ss: Data, nonce: Data, challenger: String, prover: String) -> Data? {
        guard nonce.count == nonceBytes,
              let challengerRaw = unhex(challenger), challengerRaw.count == idBytes,
              let proverRaw = unhex(prover), proverRaw.count == idBytes
        else { return nil }
        let info = infoPrefix + nonce + challengerRaw + proverRaw
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ss),
            salt: salt,
            info: info,
            outputByteCount: proofBytes
        )
        return key.withUnsafeBytes { Data($0) }
    }

    /// Whether a returned proof is the one this challenge called for.
    ///
    /// Constant-time over the whole width, and length-checked first so a
    /// malformed proof is a refusal rather than a crash.
    static func proofMatches(expected: Data, offered: Data) -> Bool {
        guard expected.count == offered.count, !expected.isEmpty else { return false }
        var diff: UInt8 = 0
        for i in 0..<expected.count {
            diff |= expected[expected.startIndex + i] ^ offered[offered.startIndex + i]
        }
        return diff == 0
    }

    // MARK: - The wire format
    //
    //   0   magic   4 bytes  "HQCH"
    //   4   version u8       1
    //   5   kind    u8       0 = challenge, 1 = proof
    //   6   from    32 bytes raw client id
    //   38  to      32 bytes raw client id
    //   70  nonce   32 bytes
    //   [challenge] u32 len + HQC ciphertext, encapsulated to `to`'s identity key
    //   [proof]     32 bytes
    //
    // Deliberately not JSON. Nothing here is AEAD-sealed, so there is no
    // canonical-header problem to solve — but there is still a
    // two-implementations problem, and the v2 envelope is the standing
    // demonstration of what JSON costs there.

    private static let magic = Data("HQCH".utf8)
    static let version: UInt8 = 1
    private static let kindChallenge: UInt8 = 0
    private static let kindProof: UInt8 = 1

    private static let offVersion = 4
    private static let offKind = 5
    private static let offFrom = 6
    private static let offTo = 38
    private static let offNonce = 70
    private static let offBody = 102
    private static let maxCtBytes = 1 << 20

    enum Kind: Equatable { case challenge, proof }

    struct Frame: Equatable {
        var kind: Kind
        /// Lowercase hex client ids.
        var from: String
        var to: String
        var nonce: Data
        /// Challenge only: HQC ciphertext encapsulated to `to`'s identity key.
        var ct: Data?
        /// Proof only.
        var proof: Data?
    }

    static func encode(_ f: Frame) -> Data? {
        guard let from = unhex(f.from), from.count == idBytes,
              let to = unhex(f.to), to.count == idBytes,
              f.nonce.count == nonceBytes
        else { return nil }

        var out = Data()
        out.reserveCapacity(offBody + 4 + (f.ct?.count ?? proofBytes))
        out += magic
        out.append(version)
        out.append(f.kind == .challenge ? kindChallenge : kindProof)
        out += from
        out += to
        out += f.nonce

        if f.kind == .challenge {
            guard let ct = f.ct, !ct.isEmpty else { return nil }
            out += u32(ct.count)
            out += ct
            return out
        }
        guard let proof = f.proof, proof.count == proofBytes else { return nil }
        out += proof
        return out
    }

    /// Decode, or nil. Never traps: this reads bytes off the network.
    static func decode(_ raw: Data) -> Frame? {
        guard raw.count >= offBody else { return nil }
        let base = raw.startIndex
        guard raw.prefix(4) == magic, raw[base + offVersion] == version else { return nil }

        let kindByte = raw[base + offKind]
        guard kindByte == kindChallenge || kindByte == kindProof else { return nil }

        let from = hex(Data(raw[(base + offFrom)..<(base + offFrom + idBytes)]))
        let to = hex(Data(raw[(base + offTo)..<(base + offTo + idBytes)]))
        let nonce = Data(raw[(base + offNonce)..<(base + offNonce + nonceBytes)])

        if kindByte == kindChallenge {
            guard raw.count >= offBody + 4 else { return nil }
            let len = (Int(raw[base + offBody]) << 24) | (Int(raw[base + offBody + 1]) << 16)
                | (Int(raw[base + offBody + 2]) << 8) | Int(raw[base + offBody + 3])
            guard len > 0, len <= maxCtBytes, raw.count == offBody + 4 + len else { return nil }
            let ct = Data(raw[(base + offBody + 4)..<(base + offBody + 4 + len)])
            return Frame(kind: .challenge, from: from, to: to, nonce: nonce, ct: ct, proof: nil)
        }
        guard raw.count == offBody + proofBytes else { return nil }
        let proof = Data(raw[(base + offBody)..<(base + offBody + proofBytes)])
        return Frame(kind: .proof, from: from, to: to, nonce: nonce, ct: nil, proof: proof)
    }

    // MARK: - Bytes

    private static func u32(_ value: Int) -> Data {
        let v = UInt32(truncatingIfNeeded: value)
        return Data([UInt8(truncatingIfNeeded: v >> 24), UInt8(truncatingIfNeeded: v >> 16),
                     UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)])
    }

    private static func hex(_ d: Data) -> String {
        d.map { String(format: "%02x", $0) }.joined()
    }

    private static func unhex(_ text: String) -> Data? {
        guard text.count % 2 == 0, !text.isEmpty else { return nil }
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
