import Foundation

/// HQC KEM smoke test (§KM-1): deterministic keygen → encapsulate → decapsulate,
/// asserting the two shared secrets match and that keygen is reproducible.
func testHQC() {
    print("[HQC-Swift] Starting Swift KEM test")

    var seedBytes = [UInt8](repeating: 0, count: HQCService.SEED_BYTES)
    for i in 0..<seedBytes.count { seedBytes[i] = UInt8(i & 0xff) }
    let seed = Data(seedBytes)

    do {
        let kp = try HQCService.generateKeypair(seed: seed)
        print("[HQC-Swift] Keypair OK (pk \(kp.publicKey.count), sk \(kp.secretKey.count))")

        // Determinism: same seed → same public key.
        let kp2 = try HQCService.generateKeypair(seed: seed)
        guard kp.publicKey == kp2.publicKey else {
            print("[HQC-Swift] ❌ keygen not deterministic")
            return
        }

        let enc = try HQCService.encapsulate(publicKey: kp.publicKey)
        let ss2 = try HQCService.decapsulate(secretKey: kp.secretKey, ciphertext: enc.ciphertext)
        guard enc.sharedSecret == ss2 else {
            print("[HQC-Swift] ❌ shared secret mismatch")
            return
        }
        print("[HQC-Swift] ✅ KEM round-trip OK (ss \(ss2.count) bytes)")
    } catch {
        print("[HQC-Swift] ❌ test failed: \(error)")
    }

    print("[HQC-Swift] Swift KEM test finished")
}
