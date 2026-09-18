//
//  Profile.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation
import SwiftData

@Model
final class Profile {
    var id: UUID
    /// Stored handle. Profiles used to carry a local display name *and* a
    /// username, which meant two names for one identity — the local one showing
    /// in the switcher and on Settings, the real one being what friends type.
    /// There is now only the username; the column keeps its old name so the
    /// store needs no migration. Read it through `username`.
    var name: String
    var createdAt: Date
    var isActive: Bool
    var publicKeyHex: String
    var seedHex: String
    /// Dead. There is no payment anywhere in this app: the product is free and
    /// the project is funded by donations, so nothing sets or reads this. The
    /// column stays only so existing stores migrate without a schema change —
    /// removing a property from a `@Model` is the one edit here that would cost
    /// a migration, and it buys nothing.
    var needsPayment: Bool?
    /// Username chosen at creation, cached locally until the first successful
    /// connect — then registered with the server. Cleared once confirmed.
    var desiredUsername: String?
    /// The home server this profile is attached to (full WebSocket URL). Optional
    /// for migration; nil means the default/official server. A profile is an
    /// identity + a home server, so each profile can live on a different server.
    var serverURL: String?

    @Relationship(deleteRule: .cascade) var friends: [Friend]?

    init(username: String, publicKeyHex: String, seedHex: String, serverURL: String? = nil) {
        self.id = UUID()
        self.name = username
        self.createdAt = Date()
        self.isActive = false
        self.publicKeyHex = publicKeyHex
        self.seedHex = seedHex
        self.serverURL = serverURL
        self.needsPayment = false  // Default to false, will be checked on connect
        self.friends = []
    }

    /// The handle this identity is known by, locally and on the server.
    var username: String {
        get { name }
        set { name = newValue }
    }

    /// The home server's HOST. A profile is an identity + a home server, and
    /// since the cutover every endpoint (auth, REST, MQTT) is derived from that
    /// one host — there is no WebSocket URL to store any more. Accepts whatever
    /// shape was saved or typed: `wss://host/ws`, `https://host`, or a bare host.
    var serverHost: String? {
        guard let raw = serverURL?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else { return nil }
        if let url = URL(string: raw), let host = url.host, !host.isEmpty { return host }
        // Bare host (possibly with a path) — take the first component.
        return raw.split(separator: "/").first.map(String.init)
    }
    
    /// Get public key as Data
    var publicKey: Data? {
        return Data(hexString: publicKeyHex)
    }

    /// This identity's CLIENT ID — `sha256(lowercase-hex(publicKeyHex))`.
    ///
    /// What the server, the broker and every peer call this profile: the MQTT
    /// client id and username, the owner of `u/{id}/presence`, and the `sender`
    /// on every frame it publishes. Derived rather than stored, because it is a
    /// pure function of a column that never changes — a stored copy could only
    /// ever be a way for the two to disagree.
    var peerID: String {
        PeerID.from(publicKeyHex: publicKeyHex)
    }
    
    /// Get seed as Data
    var seed: Data? {
        return Data(hexString: seedHex)
    }
}

