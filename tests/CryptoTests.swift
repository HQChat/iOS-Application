import Foundation
import CryptoKit

// Tests the real AESService (compiled in via run.sh).

print("AESService")

func keyData(_ k: SymmetricKey) -> Data { k.withUnsafeBytes { Data($0) } }

let message = "hello, post-quantum world 🔒"
let key = SymmetricKey(size: .bits256)

// Round-trip
let ciphertext = try! AESService.encrypt(plaintext: message, key: key)
let decrypted = try! AESService.decrypt(ciphertext: ciphertext, key: key)
check(decrypted == message, "encrypt → decrypt round-trips")
check(ciphertext != message, "ciphertext is not the plaintext")

// Nonce: same plaintext encrypts to different ciphertexts (random IV)
let ct2 = try! AESService.encrypt(plaintext: message, key: key)
check(ciphertext != ct2, "same plaintext yields different ciphertext (random IV)")

// Shared-key derivation is order-independent (both friends derive the same key)
let seedA = Data((0..<24).map { _ in UInt8.random(in: 0...255) })
let seedB = Data((0..<24).map { _ in UInt8.random(in: 0...255) })
let k1 = try! AESService.deriveSharedKey(seedA: seedA, seedB: seedB)
let k2 = try! AESService.deriveSharedKey(seedA: seedB, seedB: seedA)
check(keyData(k1) == keyData(k2), "deriveSharedKey is order-independent")

// Different seeds → different key
let k3 = try! AESService.deriveSharedKey(seedA: seedA, seedB: Data((0..<24).map { _ in 0 }))
check(keyData(k1) != keyData(k3), "different seeds yield a different key")

// Wrong key cannot decrypt
var failed = false
do { _ = try AESService.decrypt(ciphertext: ciphertext, key: SymmetricKey(size: .bits256)) }
catch { failed = true }
check(failed, "decrypt with the wrong key fails")

// --- AAD binding (must match the TS aesEncrypt/aesDecrypt `aad` parameter) --
// The v2 frame header is read to CHOOSE the key, so the payload that key opens
// cannot authenticate it. Binding it as AAD is what closes that gap; these four
// properties are the same ones asserted on the TS side.
let aadKey = SymmetricKey(size: .bits256)
let header = Data(#"{"n":7,"pn":0,"t":"msg"}"#.utf8)
let sealedWithAAD = try! AESService.encrypt(plaintext: "attack at dawn", key: aadKey, aad: header)
check((try? AESService.decrypt(ciphertext: sealedWithAAD, key: aadKey, aad: header)) == "attack at dawn",
      "AAD round-trips")

let tamperedHeader = Data(#"{"n":8,"pn":0,"t":"msg"}"#.utf8)
check((try? AESService.decrypt(ciphertext: sealedWithAAD, key: aadKey, aad: tamperedHeader)) == nil,
      "a modified header fails the tag check")
check((try? AESService.decrypt(ciphertext: sealedWithAAD, key: aadKey)) == nil,
      "dropping the header entirely fails too")

// Omitting AAD must stay byte-compatible with a sealer that never passed any,
// so every existing caller keeps working untouched.
let sealedNoAAD = try! AESService.encrypt(plaintext: "no aad here", key: aadKey)
check((try? AESService.decrypt(ciphertext: sealedNoAAD, key: aadKey)) == "no aad here",
      "omitting AAD is the old behaviour")
check((try? AESService.decrypt(ciphertext: sealedNoAAD, key: aadKey, aad: header)) == nil,
      "AAD cannot be added after the fact")

// --- Transport session keys (must match server/bot deriveSessionKeys) -------
let seed = Data((0..<24).map { _ in UInt8.random(in: 0...255) })
let keys = AESService.deriveSessionKeys(seed: seed)
check(keyData(keys.c2s).count == 32, "c2s key is AES-256 (32 bytes)")
check(keyData(keys.s2c).count == 32, "s2c key is AES-256 (32 bytes)")
check(keyData(keys.c2s) != keyData(keys.s2c), "the two directions use different keys")
let keys2 = AESService.deriveSessionKeys(seed: seed)
check(keyData(keys.c2s) == keyData(keys2.c2s), "deriveSessionKeys is deterministic")
// Pins the exact HKDF params the server/bot use (salt="salt", info="session-c2s").
let expectedC2s = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: SymmetricKey(data: seed),
    salt: "salt".data(using: .utf8)!,
    info: "session-c2s".data(using: .utf8)!,
    outputByteCount: 32)
check(keyData(keys.c2s) == keyData(expectedC2s), "c2s matches the cross-impl HKDF params")
let env = try! AESService.encrypt(plaintext: "{\"type\":\"message\"}", key: keys.c2s)
check((try? AESService.decrypt(ciphertext: env, key: keys.c2s)) == "{\"type\":\"message\"}",
      "c2s frame round-trips")
check((try? AESService.decrypt(ciphertext: env, key: keys.s2c)) == nil,
      "a c2s frame can't be read with the s2c key")

finish()
