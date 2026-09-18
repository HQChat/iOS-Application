//
//  PeerID.swift
//  DissQus
//
//  The client identifier — the Swift twin of services/server/lib/identity.ts.
//  Both sides assert the SAME test/helpers/identity-vectors.json, and the SQL
//  side asserts it too (`encode(pk_digest(pk),'hex')`), so this construction is
//  pinned three ways.
//
//      id = sha256( lowercase-hex(publicKey) )      // 64 hex characters
//
//  Everything that NAMES a contact uses this: the MQTT client id, the topic
//  strings, the friend graph, the envelope's `sender`. The 7237-byte HQC public
//  key is kept only where the key itself is needed — encapsulating to it, and
//  the safety number, which hashes the raw key BYTES and must not be switched
//  to ids (it verifies key material, not names).
//
//  ── The id is a commitment ─────────────────────────────────────────────────
//
//  Because the id is a hash of the key, a key can be checked against an id we
//  already hold: `matches(publicKeyHex:id:)` proves the key is the one that id
//  names, and second-preimage resistance means no substitute survives. That is
//  what lets the directory carry ids while the full key travels separately and
//  is VERIFIED on arrival. A key that fails is refused, never pinned.
//
//  ⚠️ An id is derivable by anyone holding the public key. It is a NAME, never
//  an authenticator.
//

import Foundation
import CryptoKit

enum PeerID {

    /// Length of an id in hex characters.
    static let length = 64

    /// The identifier for a public key given as hex.
    ///
    /// Lowercased first: the digest is over the hex TEXT, so `AB…` and `ab…`
    /// would otherwise name two different contacts for one key.
    static func from(publicKeyHex: String) -> String {
        hex(SHA256.hash(data: Data(publicKeyHex.lowercased().utf8)))
    }

    /// The identifier for a public key given as bytes.
    ///
    /// The hex conversion is done here rather than through `Data.hexString`
    /// (IdentityManager.swift) deliberately: this file has to compile with
    /// nothing but Foundation and CryptoKit, so the cross-implementation test
    /// slice in apps/apple/tests/run.sh can build it without dragging the
    /// Keychain and the native HQC library in behind it.
    static func from(publicKey: Data) -> String {
        from(publicKeyHex: hex(publicKey))
    }

    private static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// SHA-256 of a UTF-8 string, hex.
    ///
    /// Exposed because `MQTTTopics.conversation` is the same construction over a
    /// different input (the sorted pair of ids), and because the cross-impl test
    /// asserts that topic against the shared vector file. One definition of "hash
    /// this text" beats two that agree until they do not.
    static func sha256Hex(_ text: String) -> String {
        hex(SHA256.hash(data: Data(text.utf8)))
    }

    /// Whether `value` has the shape of an id. Says nothing about whether
    /// anyone holds the key behind it — see the warning above.
    static func isWellFormed(_ value: String) -> Bool {
        value.count == length && value.allSatisfy { c in
            ("0"..."9").contains(c) || ("a"..."f").contains(c)
        }
    }

    /// Whether `publicKeyHex` is the key that `id` names.
    ///
    /// The whole point of the digest. A key arriving from the server
    /// (friend-add, `GET /peer/{id}/key`) or from a peer (`init.senderPk`) is
    /// checked against the id we already hold before anything is pinned.
    static func matches(publicKeyHex: String, id: String) -> Bool {
        from(publicKeyHex: publicKeyHex) == id.lowercased()
    }

    /// Whether `publicKey` is the key that `id` names.
    static func matches(publicKey: Data, id: String) -> Bool {
        from(publicKey: publicKey) == id.lowercased()
    }
}
