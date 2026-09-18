//
//  Persistence.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation
import SwiftData

struct PersistenceController {
    static let shared = PersistenceController()

    /// DEBUG-only demo mode: launch with env `DEMO_MODE=1` to run against an
    /// in-memory store seeded with sample profiles, friends, and messages —
    /// used to screenshot the real UI without a server or live data.
    static var isDemo: Bool {
        #if DEBUG
        return ProcessInfo.processInfo.environment["DEMO_MODE"] == "1"
        #else
        return false
        #endif
    }

    @MainActor
    static let preview: ModelContainer = {
        let config = ModelConfiguration(isStoredInMemoryOnly: true)
        let container = try! ModelContainer(for: Profile.self, Friend.self, Message.self, configurations: config)
        
        // Add sample data for preview
        let sampleProfile = Profile(username: "tester", publicKeyHex: Data(count: 7237).hexString, seedHex: Data(count: 32).hexString)
        container.mainContext.insert(sampleProfile)
        
        let samplePk = Data(count: 7237)
        let sampleFriend = Friend(username: "alice",
                                  peerID: PeerID.from(publicKey: samplePk),
                                  publicKey: samplePk,
                                  profile: sampleProfile)
        container.mainContext.insert(sampleFriend)
        
        let sampleMessage = Message(content: "Hello!", isOutgoing: false, friend: sampleFriend)
        container.mainContext.insert(sampleMessage)
        
        return container
    }()
    
    let container: ModelContainer
    
    init() {
        let schema = Schema([Profile.self, Friend.self, Message.self])
        let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: Self.isDemo)

        do {
            container = try ModelContainer(for: schema, configurations: [config])
            // Encrypt the store at rest. iOS supports per-file Data Protection
            // (applied below). macOS has no FileProtectionType equivalent, so on
            // the Mac the store relies on FileVault for at-rest encryption — but
            // the identity seed/secret key are never written to this store
            // regardless (they live in the Keychain; see H1), so a readable store
            // does not expose key material.
            #if os(iOS)
            if !Self.isDemo {
                Self.applyFileProtection(to: config.url)
            }
            #endif
            if Self.isDemo {
                Self.seedDemoData(into: container)
            }
        } catch {
            // If migration fails, provide helpful error message
            // The optional needsPayment property should handle migration automatically
            // If this still fails, the user may need to delete the app's data
            fatalError("""
            Failed to create ModelContainer: \(error)
            
            This error usually occurs when the database schema has changed.
            The app will attempt to migrate automatically, but if this persists:
            
            1. Delete the app and reinstall (this will clear all data)
            2. Or manually delete the database file at:
               ~/Library/Containers/com.dissqus.DissQus/Data/Library/Application Support/default.store
            
            Note: All profiles, friends, and messages will be lost if you delete the database.
            """)
        }
    }

    #if os(iOS)
    /// Encrypt the SwiftData store at rest. `.completeUnlessOpen` keeps the
    /// file encrypted whenever the device is locked, but lets an already-open
    /// store keep working in the background (so we don't lose writes while
    /// handling messages). Applies to the SQLite file and its WAL/SHM sidecars.
    static func applyFileProtection(to url: URL) {
        let fm = FileManager.default
        let paths = [url.path, url.path + "-wal", url.path + "-shm"]
        for path in paths where fm.fileExists(atPath: path) {
            do {
                try fm.setAttributes([.protectionKey: FileProtectionType.completeUnlessOpen],
                                     ofItemAtPath: path)
            } catch {
                print("[Persistence] ⚠️ Could not set file protection on \(path): \(error)")
            }
        }
    }
    #endif

    /// An inert session, so demo contacts derive `hasSession == true` the same
    /// way a real one does. The key material is zeroed — nothing in the demo
    /// encrypts anything, and random bytes here would only look like secrets.
    private static func demoSession() -> RatchetSessionState {
        RatchetSessionState(
            root: Data(count: 32),
            rkPub: Data(count: 32),
            rkSec: Data(count: 32),
            peerRkPub: Data(count: 32),
            send: RatchetChain(ck: Data(count: 32), n: 0),
            recv: RatchetChain(ck: Data(count: 32), n: 0),
            prevSendN: 0,
            skipped: [],
            seenChains: [],
            sentOnChain: 0,
            chainStartedAt: Date()
        )
    }

    /// Populate the demo store with a believable conversation set.
    static func seedDemoData(into container: ModelContainer) {
        let context = ModelContext(container)
        let profile = Profile(username: "alexrivera",
                              publicKeyHex: Data(count: 7237).hexString,
                              seedHex: Data(count: 32).hexString)
        profile.isActive = true
        context.insert(profile)

        func friend(_ name: String, online: Bool, secure: Bool) -> Friend {
            // A real-size key, and the id it commits to. Deriving rather than
            // inventing keeps the demo store internally consistent: a screenshot
            // taken from it shows an id that really is the hash of the key beside
            // it, which is the invariant every other layer relies on.
            let pk = Data((0..<7237).map { _ in UInt8.random(in: 0...255) })
            let f = Friend(username: name,
                           peerID: PeerID.from(publicKey: pk),
                           publicKey: pk,
                           isOnline: online,
                           inviteStatus: .accepted,
                           profile: profile)
            context.insert(f)
            // "Secure" is no longer a column to set — it is derived from whether a
            // ratchet session exists. So the demo store writes a real (if inert)
            // session rather than a flag, which also keeps the screenshots honest:
            // a contact shows as ready exactly when a session would make it ready.
            if secure { f.ratchetSession = Self.demoSession() }
            return f
        }

        let sarah = friend("sarah_k", online: true, secure: true)
        _ = friend("mike99", online: true, secure: true)
        _ = friend("elena.m", online: false, secure: true)
        _ = friend("tom_dev", online: false, secure: false)
        // An invite we sent: a handle and nothing else, which is exactly what
        // `Friend.isPending` means. It used to be a zeroed 7237-byte key.
        let pending = Friend(username: "jordan",
                             isOnline: true,
                             inviteStatus: .inviteReceived,
                             profile: profile)
        context.insert(pending)

        // A short conversation with Sarah.
        let now = Date()
        let convo: [(String, Bool, TimeInterval, Message.DeliveryStatus)] = [
            ("Hey! Did the post-quantum keys sync ok?", false, -3600, .sent),
            ("Yep — handshake went through, fully encrypted 🔒", true, -3500, .delivered),
            ("Nice. Calling you in a bit to test voice", false, -3400, .sent),
            ("Standing by 👍", true, -3300, .delivered),
            ("Sent you the build too", true, -120, .queued)
        ]
        for (text, outgoing, offset, status) in convo {
            let m = Message(content: text, isOutgoing: outgoing, friend: sarah,
                            messageId: UUID().uuidString, deliveryStatus: status)
            m.timestamp = now.addingTimeInterval(offset)
            context.insert(m)
        }

        try? context.save()
    }
}
