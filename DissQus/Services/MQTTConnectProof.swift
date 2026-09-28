//
//  MQTTConnectProof.swift
//  DissQus (shared macOS + iOS)
//
//  The v1 MQTT CONNECT password: an Ed25519 signature, built locally for every
//  CONNECT, instead of an opaque bearer token fetched over HTTPS before each one.
//
//  The token was reusable for its whole 12-hour life, so anyone who saw one
//  CONNECT could connect as us, or replay the packet to take over our session.
//  Now, at sign-in and on refresh, AuthService registers the PUBLIC half of a
//  fresh per-session key, and each CONNECT signs
//
//    "hqchat-mqtt-connect/1" 0x00 clientid 0x00 keyId 0x00 ts 0x00 nonce(16 bytes)
//
//  carried as `v1.<keyId>.<ts>.<nonce b64url>.<sig b64url>`. The nonce is
//  single-use and the timestamp must be within 60 s of the server's clock, so a
//  captured CONNECT is dead on arrival. It also takes the refresh round trip out
//  of every reconnect: the proof needs no server.
//
//  Mirrors services/server/lib/mqtt-proof.ts; pinned between the two by
//  services/server/test/helpers/mqtt-proof-vectors.json
//  (apps/apple/tests/MQTTProofTests.swift reads it).
//

import Foundation
import CryptoKit

enum MQTTConnectProof {

    static let context = "hqchat-mqtt-connect/1"

    /// The exact bytes that are signed. Every field is fixed-format and none can
    /// contain 0x00, so the separators make the encoding unambiguous.
    static func message(clientID: String, keyID: String, timestamp: Int64, nonce: Data) -> Data {
        var m = Data(context.utf8)
        m.append(0)
        m.append(Data(clientID.utf8))
        m.append(0)
        m.append(Data(keyID.utf8))
        m.append(0)
        m.append(Data(String(timestamp).utf8))
        m.append(0)
        m.append(nonce)
        return m
    }

    static func password(keyID: String, timestamp: Int64, nonce: Data, signature: Data) -> String {
        "v1.\(keyID).\(timestamp).\(base64URL(nonce)).\(base64URL(signature))"
    }

    /// A fresh password for one CONNECT. `timestamp` is SERVER time — the caller
    /// applies its clock offset — because the window is judged by the server.
    static func make(clientID: String, keyID: String,
                     key: Curve25519.Signing.PrivateKey, timestamp: Int64) throws -> String {
        var nonce = Data(count: 16)
        let status = nonce.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw ProofError.randomUnavailable }
        let msg = message(clientID: clientID, keyID: keyID, timestamp: timestamp, nonce: nonce)
        let signature = try key.signature(for: msg)
        return password(keyID: keyID, timestamp: timestamp, nonce: nonce, signature: signature)
    }

    enum ProofError: Error { case randomUnavailable }

    /// base64url without padding (RFC 4648 §5), which is what the server
    /// accepts — and the ONLY spelling it accepts.
    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
