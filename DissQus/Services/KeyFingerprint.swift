//
//  KeyFingerprint.swift
//  DissQus
//
//  Pure safety-number computation (no UI), so it can be unit-tested standalone.
//  A safety number is a deterministic, symmetric fingerprint of two public keys:
//  both parties compute the same value (keys are sorted first) and compare it
//  out-of-band to confirm no server-in-the-middle swapped a key.
//

import Foundation
import CryptoKit

enum KeyFingerprint {
    /// 12 groups of 5 digits, laid out in 3 rows, derived from SHA-256 of the
    /// sorted concatenation of the two public keys.
    static func safetyNumber(myPublicKey: Data, theirPublicKey: Data) -> String {
        let combined = myPublicKey.lexicographicallyPrecedes(theirPublicKey)
            ? myPublicKey + theirPublicKey
            : theirPublicKey + myPublicKey
        let hash = Array(SHA256.hash(data: combined))
        var groups: [String] = []
        var i = 0
        while groups.count < 12 && i + 1 < hash.count {
            let v = (Int(hash[i]) << 8) | Int(hash[i + 1])
            groups.append(String(format: "%05d", v))
            i += 2
        }
        var rows: [String] = []
        for r in stride(from: 0, to: groups.count, by: 4) {
            rows.append(groups[r..<min(r + 4, groups.count)].joined(separator: " "))
        }
        return rows.joined(separator: "\n")
    }
}
