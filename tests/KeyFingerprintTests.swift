import Foundation
import CryptoKit

// Tests the real KeyFingerprint.safetyNumber (compiled in via run.sh).

print("KeyFingerprint")

let pkA = Data((0..<7237).map { _ in UInt8.random(in: 0...255) })
let pkB = Data((0..<7237).map { _ in UInt8.random(in: 0...255) })

let ab = KeyFingerprint.safetyNumber(myPublicKey: pkA, theirPublicKey: pkB)
let ba = KeyFingerprint.safetyNumber(myPublicKey: pkB, theirPublicKey: pkA)

// Symmetric: both parties (A↔B) compute the same number — the whole point.
check(ab == ba, "safety number is symmetric (both sides match)")

// Deterministic.
check(ab == KeyFingerprint.safetyNumber(myPublicKey: pkA, theirPublicKey: pkB),
      "safety number is deterministic")

// Different peer → different number (catches a swapped key).
let pkC = Data((0..<7237).map { _ in UInt8.random(in: 0...255) })
check(KeyFingerprint.safetyNumber(myPublicKey: pkA, theirPublicKey: pkC) != ab,
      "a different key yields a different safety number")

// Format: 12 groups of 5 digits across 3 rows of 4.
let rows = ab.split(separator: "\n")
check(rows.count == 3, "safety number has 3 rows")
let groups = ab.split(whereSeparator: { $0 == " " || $0 == "\n" })
check(groups.count == 12, "safety number has 12 groups")
check(groups.allSatisfy { $0.count == 5 && $0.allSatisfy(\.isNumber) },
      "every group is 5 digits")

finish()
