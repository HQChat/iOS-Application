//
//  FriendService.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import Foundation
import SwiftData

/// Friend graph mutations + secure-channel establishment.
///
/// The split after the MQTT cutover: anything about WHO you talk to is REST
/// (app-api owns the graph and, with it, the broker's topic ACL), and anything
/// carrying KEY MATERIAL is an MQTT publish on the pair's conversation topic —
/// the server is not in that path and cannot read it.
@MainActor
class FriendService: ObservableObject {

    private let session: ChatSession
    private var modelContext: ModelContext?
    private var profileManager: ProfileManager?

    init(session: ChatSession, modelContext: ModelContext? = nil, profileManager: ProfileManager? = nil) {
        self.session = session
        self.modelContext = modelContext
        self.profileManager = profileManager
    }

    func setModelContext(_ context: ModelContext) {
        self.modelContext = context
    }

    func setProfileManager(_ manager: ProfileManager) {
        self.profileManager = manager
    }

    /// Get current profile for associating friends
    private var currentProfile: Profile? {
        return profileManager?.currentProfile
    }

    /// Invite someone by username. The local row is a placeholder until the
    /// invite is accepted and the directory sync brings back their client id —
    /// and then, separately, their key.
    func sendFriendRequest(username: String) async throws {
        guard let context = modelContext else {
            throw FriendServiceError.modelContextNotSet
        }

        let profileId = currentProfile?.id
        let descriptor = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.username == username && $0.profile?.id == profileId }
        )

        if let existingFriend = try? context.fetch(descriptor).first {
            existingFriend.inviteStatus = .inviteSent
            try? context.save()
        } else {
            // No identity yet: we invited a HANDLE, and the server has not told
            // us who that is. An empty `peerID` is that state (`Friend.isPending`),
            // and it is what DirectorySync fills in when the invite is answered.
            //
            // It used to be a zeroed 7237-byte public key — a sentinel that had
            // to be recognised by "does this key contain a non-zero byte", in
            // three different files. An empty string says it once.
            let friend = Friend(username: username,
                                inviteStatus: .inviteSent, profile: currentProfile)
            context.insert(friend)
            try? context.save()
        }

        try await session.api.invite(to: username)
    }

    /// Accept an invite. The server grants both members their conversation +
    /// presence topics; the directory sync that follows fetches the peer's key
    /// and VERIFIES it against their id before pinning it — never before,
    /// because at this point we may hold nothing but a handle.
    func acceptInvite(username: String) async throws {
        try await session.api.accept(from: username)
        // Before the greeting, not after: this is the sync that fetches the
        // peer's identity key and verifies it against their id. Nothing can be
        // sealed for them until it has run.
        let friends = await session.refreshDirectory()
        if let accepted = friends.first(where: { $0.username == username }) {
            await sendOpeningGreeting(to: accepted)
        }
    }

    /// Say hello on the user's behalf, once, when a friendship begins.
    ///
    /// The point is that a conversation should not start empty and inert. A
    /// session opens on demand — as part of sending — so an accepted contact
    /// nobody has written to has no ratchet, shows no `e2e·ok`, and stays that
    /// way until somebody types first. Both people waiting for the other is the
    /// state this closes: one real message opens the channel in both directions,
    /// because the frame carries the handshake.
    ///
    /// It also gives the pair something to point at. A greeting that names both
    /// handles is a line either side can read back when they compare safety
    /// numbers, which is a nicer prompt than an empty thread.
    ///
    /// ⚠️ It is NOT a tamper check, and should not be described as one. The text
    /// is chosen by the sending app and sealed end to end, so anyone able to
    /// substitute keys could equally rewrite it. What actually refuses a
    /// substituted key is the identifier being a commitment to it
    /// (`Friend.pin(publicKeyHex:)` stores nothing that does not hash to the
    /// contact's id) and, for the human, the safety number.
    private func sendOpeningGreeting(to friend: Friend) async {
        // Once ever. `messages` is empty only before anything has been said in
        // either direction, so this cannot fire on a re-accept, a second device
        // syncing the same friendship, or a contact removed and added again with
        // history kept.
        guard friend.messages?.isEmpty ?? true else { return }
        guard friend.hasPinnedKey, !friend.isVanished else { return }
        let me = currentProfile?.username ?? "someone"
        await session.sendText("hello @\(friend.username), i'm @\(me).", to: friend)
    }

    /// Force an asymmetric ratchet step on the next message to `friend`.
    ///
    /// The ratchet steps on its own — on direction flips, subject to a rate
    /// limit — so this is a user-facing "rotate now", not a mechanism the
    /// protocol depends on. v1 needed an explicit `rotateKeys` because nothing
    /// else ever rotated: a conversation under 100 messages lived its whole life
    /// on one static key.
    ///
    /// Implemented by ageing the current sending chain rather than stepping
    /// immediately: a step has to ride on a real message (it carries a ciphertext
    /// the peer decapsulates), so sending an empty frame just to rotate would be
    /// a message the user did not write.
    func forceRatchetStep(friend: Friend) {
        guard var session = friend.ratchetSession else { return }
        session.chainStartedAt = .distantPast
        friend.ratchetSession = session
        try? modelContext?.save()
    }

    /// Delete a vanished contact and everything under it.
    ///
    /// There is no `acceptKeyChange` any more, and there cannot be. It re-pinned
    /// a contact to a new key in place — which is not a state that exists once
    /// the identifier IS the key: a different key is a different id, so what used
    /// to look like "this contact re-keyed" is now one identity ending and
    /// another beginning. DirectorySync marks the old row vanished and adds the
    /// new one beside it.
    ///
    /// What is left for the user to decide is whether to keep the old history.
    /// This is the "no, remove it" half; doing nothing keeps it, read-only,
    /// which is the default because the messages are theirs.
    ///
    /// Only ever called on a vanished row: a live contact is removed through
    /// `removeFriend`, which also has a server side to it. This one does not —
    /// the friendship is already gone, which is why the identity vanished.
    func forgetVanished(friend: Friend) {
        guard friend.isVanished, let context = modelContext else { return }
        friend.clearAESKeys()
        context.delete(friend)
        try? context.save()
    }

    /// Remove a contact the user picked off a list.
    ///
    /// Dispatching on the ROW rather than on the username, because after an
    /// identity change two rows share a handle. `removeFriend(username:)` would
    /// resolve that handle on the server — reaching the NEW identity — so
    /// deleting the old, unreachable one would silently unfriend the live
    /// contact. A vanished row has no server side left to remove.
    func remove(friend: Friend) async throws {
        if friend.isVanished {
            forgetVanished(friend: friend)
            return
        }
        try await removeFriend(username: friend.username)
    }

    // MARK: - Blocking (App Store Guideline 1.2)

    /// Block a contact.
    ///
    /// One call: the server unfriends them, revokes both members' MQTT topics,
    /// drops any pending invite in either direction, and writes a row that
    /// survives all of it — without which the blocked party simply re-invites
    /// and the block has evaporated.
    ///
    /// ⚠️ The local row is KEPT and marked, not deleted, and that is the whole
    /// point of `Friend.blockedAt`. A blocked peer is absent from `/friends` by
    /// construction, and `DirectorySync.reconcileRemovals` deletes local rows the
    /// directory stops naming — so without the flag this would destroy the
    /// conversation the user blocked somebody over, on the next poll.
    func block(friend: Friend) async throws {
        guard !friend.peerID.isEmpty else { return }
        try await session.api.block(peer: friend.peerID)
        friend.blockedAt = Date()
        try? modelContext?.save()
    }

    /// Lift a block. Does NOT restore the friendship on either side — the pair
    /// re-invite like strangers, which is what an ordinary unfriend leaves
    /// behind too. The local history stays where it is.
    func unblock(friend: Friend) async throws {
        guard !friend.peerID.isEmpty else { return }
        try await session.api.unblock(peer: friend.peerID)
        friend.blockedAt = nil
        try? modelContext?.save()
    }

    /// Get all friends
    func getAllFriends() throws -> [Friend] {
        guard let context = modelContext else {
            throw FriendServiceError.modelContextNotSet
        }
        let descriptor = FetchDescriptor<Friend>()
        return try context.fetch(descriptor)
    }

    /// Get friend by username
    func getFriend(username: String) throws -> Friend? {
        guard let context = modelContext else {
            throw FriendServiceError.modelContextNotSet
        }
        let descriptor = FetchDescriptor<Friend>(
            predicate: #Predicate { $0.username == username }
        )
        return try context.fetch(descriptor).first
    }

    /// Re-read the friend graph from the server (there is no push channel for it
    /// any more — see DirectorySync).
    func requestFriendsList() async throws {
        await session.refreshDirectory()
    }

    func requestInvitesList() async throws {
        await session.refreshDirectory()
    }

    /// Withdraw an invite we sent, or decline one we received. The server figures
    /// out which direction applies. `removeFriend` can't do this — it requires an
    /// established friendship.
    func cancelInvite(username: String) async throws {
        try await session.api.cancelInvite(peer: username)
        guard let context = modelContext else { return }
        let profileId = currentProfile?.id
        let descriptor = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.username == username && $0.profile?.id == profileId }
        )
        if let friend = try? context.fetch(descriptor).first,
           friend.inviteStatus != .accepted, !friend.isVanished {
            friend.clearAESKeys()
            context.delete(friend)
            try? context.save()
        }
    }

    func removeFriend(username: String) async throws {
        guard let context = modelContext else {
            throw FriendServiceError.modelContextNotSet
        }

        let profileId = currentProfile?.id
        let descriptor = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.username == username && $0.profile?.id == profileId }
        )

        // A vanished identity is not a friendship the server still holds, so
        // removing it is a local decision (`forgetVanished`) rather than a call.
        // Picking the live row matters: after an identity change two rows share
        // a username, and deleting the wrong one throws away the live contact
        // while leaving the dead one.
        let rows = (try? context.fetch(descriptor)) ?? []
        if let friend = rows.first(where: { !$0.isVanished }) ?? rows.first {
            // Stop following their topics before the row (and its key) is gone.
            await session.unsubscribe(friend: friend)
            friend.clearAESKeys() // remove key material from the Keychain too
            context.delete(friend)
            try? context.save()
        }

        try await session.api.remove(peer: username)
    }
}

// MARK: - Errors

enum FriendServiceError: LocalizedError {
    case friendNotFound
    case seedGenerationFailed
    case missingSeeds
    case encryptionFailed
    case modelContextNotSet

    var errorDescription: String? {
        switch self {
        case .friendNotFound:
            return "Friend not found"
        case .seedGenerationFailed:
            return "Failed to generate random seed"
        case .missingSeeds:
            return "Missing seeds for key derivation"
        case .encryptionFailed:
            return "Failed to encrypt seed"
        case .modelContextNotSet:
            return "Model context not set"
        }
    }
}
