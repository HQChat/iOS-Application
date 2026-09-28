//
//  NoiseHQN.swift
//  DissQus (shared macOS + iOS)
//
//  hqn/1 — the client half of the hybrid post-quantum Noise handshake that
//  carries MQTT over raw TCP to the gateway in front of the broker.
//
//  The protocol is specified in services/server/lib/noise.ts; this mirrors it
//  byte for byte. In short:
//
//    Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256
//    <- s, s_pq                 both server statics pinned in the app
//    -> e, es, kem, [CONNECT]   msg1: the MQTT CONNECT rides in the first flight
//    <- e, ee, [payload]        msg2
//
//  So a connect costs TCP's round trip plus one, like plaintext MQTT, while the
//  stream is encrypted, authenticated, and post-quantum (HQC-256 alongside
//  X25519: breaking either alone recovers nothing).
//
//  Wire: [version u8][keyId u8] in the clear (both in the prologue), then every
//  message and transport frame as a u16 big-endian length plus its bytes.
//
//  Held to the TypeScript implementation by
//  services/server/test/helpers/noise-hqn-vectors.json, which
//  apps/apple/tests/NoiseHQNTests.swift reads.
//

import Foundation
import CryptoKit

enum NoiseHQN {

    static let version: UInt8 = 1
    static let protocolName = "Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256"
    static let prologueLabel = "hqchat-noise/1"

    static let dhLength = 32
    static let tagLength = 16
    static let maxFrame = 65535
    static let maxFramePlaintext = maxFrame - tagLength

    static let hqcPublicKeyBytes = 7237
    static let hqcCiphertextBytes = 14421
    static let hqcSharedSecretBytes = 32

    enum NoiseError: Error, Equatable {
        case badKeySize
        case lowOrderPoint
        case decryptionFailed
        case nonceExhausted
        case messageTooShort
        case wrongState
        case frameTooLarge
        case kemFailed
    }

    /// A server's pinned public statics, as the app ships them.
    struct ServerKeys: Equatable {
        let keyID: UInt8
        let x25519: Data
        let hqc: Data
    }

    /// HQC-256 encapsulation, injected so vectors can pin the (ct, ss) pair —
    /// real encapsulation is randomized.
    typealias Encapsulate = (_ publicKey: Data) throws -> (ciphertext: Data, sharedSecret: Data)

    static func prologue(version: UInt8, keyID: UInt8) -> Data {
        var p = Data(prologueLabel.utf8)
        p.append(version)
        p.append(keyID)
        return p
    }

    // MARK: - Primitives

    static func dh(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pub: Data) throws -> Data {
        guard pub.count == dhLength else { throw NoiseError.badKeySize }
        let peer: Curve25519.KeyAgreement.PublicKey
        let shared: SharedSecret
        do {
            peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub)
            shared = try priv.sharedSecretFromKeyAgreement(with: peer)
        } catch {
            throw NoiseError.lowOrderPoint
        }
        let out = shared.withUnsafeBytes { Data($0) }
        // A low-order point would let an attacker fix the secret to a known value.
        guard out.contains(where: { $0 != 0 }) else { throw NoiseError.lowOrderPoint }
        return out
    }

    static func hash(_ parts: Data...) -> Data {
        var h = SHA256()
        for p in parts { h.update(data: p) }
        return Data(h.finalize())
    }

    static func hmac(_ key: Data, _ parts: Data...) -> Data {
        var h = HMAC<SHA256>(key: SymmetricKey(data: key))
        for p in parts { h.update(data: p) }
        return Data(h.finalize())
    }

    /// The Noise HKDF: two 32-byte outputs.
    static func hkdf2(_ chainingKey: Data, _ ikm: Data) -> (Data, Data) {
        let temp = hmac(chainingKey, ikm)
        let out1 = hmac(temp, Data([1]))
        let out2 = hmac(temp, out1, Data([2]))
        return (out1, out2)
    }

    // MARK: - CipherState / SymmetricState

    final class CipherState {
        private let key: SymmetricKey?
        private(set) var nonce: UInt64 = 0

        init(key: Data?) { self.key = key.map { SymmetricKey(data: $0) } }

        /// 32 zero bits, then the counter little-endian.
        private func nonceBytes() throws -> ChaChaPoly.Nonce {
            var n = Data(count: 4)
            withUnsafeBytes(of: nonce.littleEndian) { n.append(contentsOf: $0) }
            return try ChaChaPoly.Nonce(data: n)
        }

        func encrypt(ad: Data, _ plaintext: Data) throws -> Data {
            guard let key else { return plaintext }
            guard nonce < UInt64.max else { throw NoiseError.nonceExhausted }
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonceBytes(), authenticating: ad)
            nonce += 1
            return box.ciphertext + box.tag
        }

        func decrypt(ad: Data, _ ciphertext: Data) throws -> Data {
            guard let key else { return ciphertext }
            guard nonce < UInt64.max else { throw NoiseError.nonceExhausted }
            guard ciphertext.count >= NoiseHQN.tagLength else { throw NoiseError.decryptionFailed }
            let body = ciphertext.prefix(ciphertext.count - NoiseHQN.tagLength)
            let tag = ciphertext.suffix(NoiseHQN.tagLength)
            do {
                let box = try ChaChaPoly.SealedBox(nonce: nonceBytes(), ciphertext: body, tag: tag)
                let out = try ChaChaPoly.open(box, using: key, authenticating: ad)
                nonce += 1
                return out
            } catch {
                throw NoiseError.decryptionFailed
            }
        }

        /// Test hook: jump the counter to check the exhaustion guard.
        func __setNonceForTesting(_ n: UInt64) { nonce = n }
    }

    final class SymmetricState {
        private(set) var ck: Data
        private(set) var h: Data
        private var cs = CipherState(key: nil)

        init(protocolName: String) {
            let name = Data(protocolName.utf8)
            h = name.count <= 32 ? name + Data(count: 32 - name.count) : NoiseHQN.hash(name)
            ck = h
        }

        func mixKey(_ ikm: Data) {
            let (newCK, k) = NoiseHQN.hkdf2(ck, ikm)
            ck = newCK
            cs = CipherState(key: k)
        }

        func mixHash(_ data: Data) { h = NoiseHQN.hash(h, data) }

        func encryptAndHash(_ plaintext: Data) throws -> Data {
            let ct = try cs.encrypt(ad: h, plaintext)
            mixHash(ct)
            return ct
        }

        func decryptAndHash(_ ciphertext: Data) throws -> Data {
            let pt = try cs.decrypt(ad: h, ciphertext)
            mixHash(ciphertext)
            return pt
        }

        func split() -> (CipherState, CipherState) {
            let (k1, k2) = NoiseHQN.hkdf2(ck, Data())
            return (CipherState(key: k1), CipherState(key: k2))
        }
    }

    // MARK: - The client's handshake

    struct Transport {
        /// Client → server.
        let send: CipherState
        /// Server → client.
        let receive: CipherState
        /// Identical on both ends: a channel binding.
        let handshakeHash: Data
    }

    final class Initiator {
        private let server: ServerKeys
        private let state: SymmetricState
        private let ephemeral: Curve25519.KeyAgreement.PrivateKey
        private let encapsulate: Encapsulate
        private var sent = false

        init(server: ServerKeys,
             version: UInt8 = NoiseHQN.version,
             ephemeral: Curve25519.KeyAgreement.PrivateKey = .init(),
             encapsulate: @escaping Encapsulate) throws {
            guard server.x25519.count == NoiseHQN.dhLength,
                  server.hqc.count == NoiseHQN.hqcPublicKeyBytes else { throw NoiseError.badKeySize }
            self.server = server
            self.ephemeral = ephemeral
            self.encapsulate = encapsulate
            state = SymmetricState(protocolName: NoiseHQN.protocolName)
            state.mixHash(NoiseHQN.prologue(version: version, keyID: server.keyID))
            state.mixHash(server.x25519)
            state.mixHash(server.hqc)
        }

        /// msg1 = e ‖ enc(ct) ‖ enc(payload).
        func writeMessage1(payload: Data) throws -> Data {
            guard !sent else { throw NoiseError.wrongState }
            sent = true
            let e = ephemeral.publicKey.rawRepresentation
            state.mixHash(e)
            state.mixKey(try NoiseHQN.dh(ephemeral, server.x25519))
            let kem: (ciphertext: Data, sharedSecret: Data)
            do { kem = try encapsulate(server.hqc) } catch { throw NoiseError.kemFailed }
            guard kem.ciphertext.count == NoiseHQN.hqcCiphertextBytes,
                  kem.sharedSecret.count == NoiseHQN.hqcSharedSecretBytes else { throw NoiseError.kemFailed }
            let encCT = try state.encryptAndHash(kem.ciphertext)
            state.mixKey(kem.sharedSecret)
            let encPayload = try state.encryptAndHash(payload)
            return e + encCT + encPayload
        }

        /// msg2 = re ‖ enc(payload).
        func readMessage2(_ message: Data) throws -> (payload: Data, transport: Transport) {
            guard sent else { throw NoiseError.wrongState }
            guard message.count >= NoiseHQN.dhLength + NoiseHQN.tagLength else { throw NoiseError.messageTooShort }
            let re = Data(message.prefix(NoiseHQN.dhLength))
            state.mixHash(re)
            state.mixKey(try NoiseHQN.dh(ephemeral, re))
            let payload = try state.decryptAndHash(Data(message.dropFirst(NoiseHQN.dhLength)))
            let (c1, c2) = state.split()
            return (payload, Transport(send: c1, receive: c2, handshakeHash: state.h))
        }
    }

    // MARK: - Framing

    static func frame(_ body: Data) throws -> Data {
        guard body.count <= maxFrame else { throw NoiseError.frameTooLarge }
        var out = Data([UInt8(body.count >> 8), UInt8(body.count & 0xFF)])
        out.append(body)
        return out
    }

    /// Encrypt a chunk of the byte stream into as few frames as it needs —
    /// ONE for anything an MQTT packet ordinarily is, so a small publish is one
    /// segment on the wire.
    static func sealFrames(_ cs: CipherState, _ data: Data) throws -> Data {
        var out = Data()
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = min(offset + maxFramePlaintext, data.endIndex)
            out.append(try frame(try cs.encrypt(ad: Data(), Data(data[offset..<end]))))
            offset = end
        }
        return out
    }

    /// Rolling reader of length-prefixed frames. Drained after every `push`, it
    /// holds at most one partial frame — 65537 bytes, whatever the peer sends.
    struct FrameReader {
        private var buffer = Data()

        mutating func push(_ chunk: Data) { buffer.append(chunk) }

        mutating func next() -> Data? {
            guard buffer.count >= 2 else { return nil }
            let start = buffer.startIndex
            let length = Int(buffer[start]) << 8 | Int(buffer[start + 1])
            guard buffer.count >= 2 + length else { return nil }
            let body = Data(buffer[(start + 2)..<(start + 2 + length)])
            buffer = Data(buffer.dropFirst(2 + length))
            return body
        }

        var pending: Int { buffer.count }
    }
}

// MARK: - Endpoint

/// Where an hqn/1 gateway is and which keys to pin. From `Deployment` for the
/// default server, or from `GET /auth/transport` over the pinned HTTPS API for
/// any other. Lives here, beside the protocol, so configuration code can name it
/// without pulling in the transport.
struct HQNEndpoint: Equatable {
    let host: String
    let port: UInt16
    /// Every key id the server may be using — current and next, for rotation.
    let keys: [NoiseHQN.ServerKeys]

    /// `hqn://host:port` — what MQTTBackend.connect is handed.
    var url: URL { URL(string: "hqn://\(host):\(port)")! }

    /// Parse the `hqn` object of a `/auth/transport` response. Nil for anything
    /// incomplete or malformed: a bad answer must leave the client on WSS.
    static func parse(_ json: [String: Any]) -> HQNEndpoint? {
        guard let host = json["host"] as? String, !host.isEmpty,
              host.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }),
              let port = json["port"] as? Int, (1...65535).contains(port),
              let raw = json["keys"] as? [[String: Any]] else { return nil }
        let keys: [NoiseHQN.ServerKeys] = raw.compactMap { k in
            guard let id = k["keyId"] as? Int, (0...255).contains(id),
                  let x = (k["x25519"] as? String).flatMap({ Data(base64Encoded: $0) }), x.count == 32,
                  let q = (k["hqc"] as? String).flatMap({ Data(base64Encoded: $0) }),
                  q.count == NoiseHQN.hqcPublicKeyBytes else { return nil }
            return NoiseHQN.ServerKeys(keyID: UInt8(id), x25519: x, hqc: q)
        }
        guard !keys.isEmpty else { return nil }
        return HQNEndpoint(host: host, port: UInt16(port), keys: keys)
    }
}

