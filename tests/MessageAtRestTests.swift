//
//  MessageAtRestTests.swift
//
//  Proves the at-rest guarantee end to end against a REAL on-disk SwiftData
//  store: a message body written through `Message.content` must not appear as
//  plaintext anywhere in the store file, must read back correctly through the
//  owning profile's key, and must be unreadable under any other profile.
//

import Foundation
import SwiftData
import CryptoKit

// MARK: - Stubs
// `Profile` reads ServerConfig for its fallback URL, and the models use the hex
// helpers that live in IdentityManager — neither of which is worth compiling
// (LocalAuthentication, the HQC bridge) to test the storage layer.

enum ServerConfig {
    static let webSocketURL = URL(string: "wss://example.invalid/ws")!
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            guard var byte = UInt8(hexString[i..<j], radix: 16) else { return nil }
            data.append(&byte, count: 1)
            i = j
        }
        self = data
    }
}

// MARK: - Fixture

let secret = "meet me at the pier at midnight"
let storeDir = URL(fileURLWithPath: NSTemporaryDirectory())
    .appendingPathComponent("hqchat-atrest-\(UUID().uuidString)")
try! FileManager.default.createDirectory(at: storeDir, withIntermediateDirectories: true)
let storeURL = storeDir.appendingPathComponent("test.store")

let schema = Schema([Profile.self, Friend.self, Message.self])
let container = try! ModelContainer(
    for: schema,
    configurations: [ModelConfiguration(schema: schema, url: storeURL)]
)
let context = ModelContext(container)

let profile = Profile(username: "tester",
                      publicKeyHex: Data(count: 32).hexString,
                      seedHex: Data(count: 32).hexString)
context.insert(profile)
let friend = Friend(username: "peer", publicKey: Data(count: 32), profile: profile)
context.insert(friend)

let message = Message(content: secret, isOutgoing: false, friend: friend)
context.insert(message)
try! context.save()

// 1. The body round-trips through the owning profile's key.
check(message.content == secret, "content reads back as plaintext in memory")

// 2. …and it is NOT in the store file. This is the actual guarantee: anyone
//    reading the database off the device sees ciphertext.
let onDisk: Data = {
    var bytes = (try? Data(contentsOf: storeURL)) ?? Data()
    for suffix in ["-wal", "-shm"] {
        let sidecar = URL(fileURLWithPath: storeURL.path + suffix)
        if let extra = try? Data(contentsOf: sidecar) { bytes.append(extra) }
    }
    return bytes
}()
let secretBytes = Data(secret.utf8)
// Can this environment seal at all? The message key pair is generated in the
// Secure Enclave with no fallback, and an Enclave is exactly what a headless
// unsigned binary does not have (macOS returns -25308; the iOS Simulator
// -25293). Where it cannot seal, the checks below are not failing — they are
// unable to run, and saying so is the difference between a known gap and a
// mystery.
let canSeal: Bool = {
    let probeProfile = UUID()
    return MessageKeyStore.wrap(SymmetricKey(size: .bits256), for: probeProfile) != nil
}()
let noEnclave = "no Secure Enclave here; at-rest sealing needs a signed build on real hardware"

check(!onDisk.isEmpty, "store file is readable")
check(onDisk.range(of: secretBytes) == nil, "plaintext does not appear in the store file")
if !canSeal {
    print("    (note: nothing could be sealed here, so the check above proves only "
          + "that a failed seal persists NOTHING — which is itself the guarantee "
          + "that the removed symmetric floor used to provide by other means.)")
}

// 3. Re-opening the store decrypts (the key came from the Keychain, not the file).
let reread = ModelContext(container)
let fetched = try! reread.fetch(FetchDescriptor<Message>())
check(fetched.count == 1, "one message round-tripped")
if canSeal {
    check(fetched.first?.content == secret, "content decrypts after a fresh fetch")
} else {
    skip("content decrypts after a fresh fetch", because: noEnclave)
}

// 4. Another profile cannot read it. Re-point the row at a different profile,
//    save, and reopen the store: on a fresh read there is no key that opens
//    this body, so it comes back as the placeholder rather than the plaintext.
//    (The in-memory object keeps its already-decrypted copy — that plaintext
//    was legitimately readable in this process — so the check reopens instead.)
let foreignProfileID = UUID()
message.profileID = foreignProfileID
try! context.save()

let reopened = try! ModelContainer(
    for: schema,
    configurations: [ModelConfiguration(schema: schema, url: storeURL)]
)
let foreignRead = try! ModelContext(reopened).fetch(FetchDescriptor<Message>())
if canSeal {
    check(foreignRead.first?.content == Message.unreadableBody,
          "a foreign profile cannot open the body")
} else {
    skip("a foreign profile cannot open the body", because: noEnclave)
}

// 5. Message keys never live in the store.
check(!MessageKeyStore.hasKey(for: UUID()), "no key is minted for an unknown profile")

// MARK: - TM-3: the envelope, and the fallback that must never be plaintext
//
// The hybrid scheme (a per-message key wrapped to a `.userPresence` key pair)
// cannot be exercised here: this binary is not a signed app, so creating an
// access-controlled key fails and the store falls back to the symmetric floor.
// What CAN be asserted headlessly is the property that matters most — that the
// fallback is a fallback to CIPHERTEXT, not to plaintext. An earlier version of
// this change returned nil from seal() on that path, which made `content` store
// the body in the clear; the test above caught it, and this pins it down.

print("")
print("At-rest envelope (TM-3)")

let fbProfile = UUID()
let probe = "fallback-probe-\(UUID().uuidString)"
let fbMessage = Message(content: probe, isOutgoing: true, profileID: fbProfile)

// Holds either way, and is the invariant that matters most: a body is never
// written to the store in the clear, whether it was sealed or the seal failed.
check(fbMessage.content == probe && !fbMessage.needsAtRestEncryption,
      "never stored in the clear")

if canSeal {
    check(fbMessage.content == probe, "a sealed row reads back through the same API")
} else {
    skip("a sealed row reads back through the same API", because: noEnclave)
}

MessageKeyStore.delete(for: fbProfile)

// Cleanup: Keychain items outlive the temp store.
MessageKeyStore.delete(for: profile.id)
try? FileManager.default.removeItem(at: storeDir)

finish()
