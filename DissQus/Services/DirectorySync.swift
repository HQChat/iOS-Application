import Foundation
import SwiftData

fileprivate func dlog(_ message: @autoclosure () -> String) {
    #if DEBUG
    Swift.print(message())
    #endif
}

/// Pulls the friend graph from app-api (REST) into the local store.
///
/// Under `/ws` the graph arrived as a stream of pushed events (`friends_list`,
/// `friend_added`, `friend_request`, `friend_removed`, …). The control plane is
/// REST now, so the client asks instead of waiting: once on login, and again
/// after any mutation it performs. That is a deliberate simplification for V0 —
/// the events that used to arrive unprompted (someone invites you while the app
/// is open) surface on the next sync rather than instantly.
///
/// ── What the server sends, and what it cannot lie about ─────────────────────
///
/// The directory carries CLIENT IDS: `sha256(lowercase-hex(publicKey))`, 64
/// characters. It used to carry the key itself — 14474 characters per friend, on
/// a poll that runs every sixty seconds.
///
/// The key is fetched separately, once, and VERIFIED before it is pinned
/// (`Friend.pin(publicKeyHex:)`). That check is the point of the identifier
/// being a digest: a compromised server handing each side its own key is how
/// "E2E" gets MITM'd, and second-preimage resistance means no substitute
/// survives. TOFU narrows to "trust the id the graph first gave you".
///
/// ── A changed key is a changed IDENTITY ─────────────────────────────────────
///
/// The old handler parked a changed key in `pendingKeyHex` and asked the user to
/// accept it. That state cannot exist now: a different key IS a different id, so
/// "this contact re-keyed" is not representable. What is representable is that
/// their identity VANISHED and a new one appeared under the same handle — a
/// reinstall, an account reset, a new device. The old row is kept, unreachable
/// and read-only; the new one is a separate contact that must earn its own
/// verification.
///
/// Detection lives here, and it works exactly the way it did: a lookup by
/// identifier MISSES when the identity changed, so the USERNAME fallback is the
/// detection path. That is why the row carries both.
@MainActor
final class DirectorySync {

    private let api: APIClient
    private let modelContext: ModelContext
    private let profileManager: ProfileManager?

    init(api: APIClient, modelContext: ModelContext, profileManager: ProfileManager?) {
        self.api = api
        self.modelContext = modelContext
        self.profileManager = profileManager
    }

    private var currentProfile: Profile? { profileManager?.currentProfile }

    /// Fetch friends + invites and reconcile them into SwiftData.
    /// Returns the friends that now hold a client id, so the caller can subscribe
    /// to their topics.
    @discardableResult
    func sync() async throws -> [Friend] {
        guard let profile = currentProfile else { return [] }
        let profileId = profile.id

        let friends = try await api.getFriends()
        let invites = try await api.getInvites()

        // ── Blocked contacts, and why this is fetched before anything is deleted
        //
        // Blocking a contact tears the friendship down, so a blocked peer is
        // ABSENT from /friends by construction — and absence is exactly what
        // `reconcileRemovals` below reads as "delete this row and purge its
        // Keychain material". Without this list, blocking somebody destroys the
        // conversation they were blocked over, on the next sixty-second poll.
        //
        // `nil` means the server did not answer, which is NOT the same as "the
        // list is empty" and must never be flattened into it. On a failure this
        // sync skips removals entirely: a contact that lingers one extra cycle
        // costs nothing, and a deleted history cannot be got back.
        let blockedIDs: Set<String>?
        do { blockedIDs = Set(try await api.getBlocked()) }
        catch {
            dlog("[DirectorySync] ⚠️ could not read the block list (\(error)) — "
                 + "skipping removals this cycle rather than risking a blocked contact")
            blockedIDs = nil
        }

        // Every identity the server listed, in either direction. Passed into
        // `upsert` as well as `reconcileRemovals`: an identity the server still
        // lists has plainly not vanished, whatever its display name collides
        // with.
        let serverIDs = Set(friends.map { $0.id }).union(invites.map { $0.id })

        var known: [Friend] = []
        for dto in friends {
            guard let row = upsert(id: dto.id, username: label(dto.username, dto.id),
                                   status: .accepted, profileId: profileId,
                                   serverIDs: serverIDs) else { continue }
            known.append(row)
        }

        for invite in invites {
            if let row = upsert(id: invite.id, username: label(invite.username, invite.id),
                                status: .inviteReceived, profileId: profileId,
                                serverIDs: serverIDs) {
                known.append(row)
            }
        }

        if let blockedIDs {
            reconcileBlocks(blockedIDs: blockedIDs, profileId: profileId)
            reconcileRemovals(serverIDs: serverIDs, profileId: profileId)
        }

        // Only when there is something to write. This runs on a timer now
        // (`ChatSession.startDirectoryPoll`), and a save with no changes still
        // announces itself — which is what churns the views that list
        // conversations, and cancelling their `.task` is how the unlock request
        // went missing in #84.
        if modelContext.hasChanges { try? modelContext.save() }

        // Fetch whatever keys we are missing. Only rows that have none: a key is
        // 14474 characters and does not change for a given id, so this is once
        // per contact ever, not once per poll.
        await fetchMissingKeys(for: known)
        if modelContext.hasChanges { try? modelContext.save() }

        NotificationService.shared.refreshCounts(modelContext: modelContext, profileID: profileId)
        return known
    }

    /// Fetch and verify the identity key for any contact we do not have one for.
    ///
    /// Best-effort and per-contact: a server that will not answer for one person
    /// must not stop the rest of the sync, and a contact without a key is a
    /// perfectly ordinary state — the session simply cannot open until it has one.
    private func fetchMissingKeys(for friends: [Friend]) async {
        for friend in friends where !friend.hasPinnedKey && !friend.peerID.isEmpty {
            let id = friend.peerID
            let served: String?
            do { served = try await api.peerKey(id: id) } catch {
                dlog("[DirectorySync] could not fetch \(friend.username)'s key: \(error)")
                ProtocolLog.record(.dropped(stage: "key-fetch", peerID: id,
                                            reason: "GET /peer/{id}/key failed"))
                continue
            }
            guard let served else {
                dlog("[DirectorySync] the server knows no key for \(friend.username) (\(id.prefix(8))…)")
                ProtocolLog.record(.dropped(stage: "key-fetch", peerID: id,
                                            reason: "server knows no key for this id"))
                continue
            }
            if friend.pin(publicKeyHex: served) {
                dlog("[DirectorySync] 🔑 pinned \(friend.username)'s key, verified against their id")
                ProtocolLog.record(.keyFetched(peer: id, verified: true))
                ProtocolLog.record(.keyPinned(peer: id, source: .directory))
            } else {
                ProtocolLog.record(.keyFetched(peer: id, verified: false))
                ProtocolLog.record(.keyRejected(peer: id,
                                                reason: "served key does not hash to the id"))
                // Loud, and refused. Either the server is lying or its directory
                // and its key store disagree; both mean this key must not be
                // encrypted to. There is nothing for the user to decide here —
                // the arithmetic already decided.
                dlog("[DirectorySync] 🚨 the key served for \(friend.username) does NOT hash to "
                     + "their id (\(id.prefix(8))…) — refusing it")
            }
        }
    }

    /// What to call a peer who has not claimed a handle.
    ///
    /// Their ID, shortened — not a shared word like "Anonymous". A placeholder
    /// every nameless account has in common would collide in `upsert`'s
    /// username fallback below, and the fallback is exactly how a re-keyed
    /// contact is detected: two nameless peers would read as one of them having
    /// vanished. The server sends null for these rather than deciding for us.
    private func label(_ username: String?, _ id: String) -> String {
        guard let username, !username.isEmpty else { return String(id.prefix(8)) }
        return username
    }

    /// Find (by id, then by username for rows created locally before the id was
    /// known) or create the row, and apply the server's view of it.
    // Not `private`, like the two reconcile passes below: the vanished-marking
    // branch decides whether a contact is shown as an impersonation warning, and
    // that is worth driving rather than reading.
    func upsert(id: String, username: String,
                        status: Friend.InviteStatus, profileId: UUID,
                        serverIDs: Set<String>) -> Friend? {
        guard PeerID.isWellFormed(id) else { return nil }

        let byID = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.peerID == id && $0.profile?.id == profileId }
        )
        if let existing = try? modelContext.fetch(byID).first {
            if existing.username != username { existing.username = username }
            // An identity that is listed again is not vanished. This is the
            // benign case the state has to survive: a transient sync that did
            // not list someone, followed by one that does.
            if existing.isVanished { existing.vanishedAt = nil }
            advance(existing, to: status)
            return existing
        }

        // A row we created ourselves when the invite was sent carries a username
        // and no id; this is where it gets its real one. Only rows that are still
        // waiting — one that already HAS an id is a different identity, handled
        // below.
        let byName = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.username == username && $0.profile?.id == profileId }
        )
        let sameName = (try? modelContext.fetch(byName)) ?? []

        if let waiting = sameName.first(where: { $0.isPending }) {
            waiting.peerID = id
            advance(waiting, to: status)
            dlog("[DirectorySync] ✅ \(username) answered — id \(id.prefix(8))…")
            return waiting
        }

        // Same handle, different identity, and the server no longer lists the
        // old one. Their key changed, which means their id changed, which means
        // the contact we had does not exist any more.
        //
        // The `serverIDs` guard is what keeps this from firing on a name
        // collision: an identity the server still lists has not vanished, so a
        // row is only retired when the directory has actually stopped naming it.
        //
        // NOT merged, and NOT deleted. Merging would carry a verification the new
        // key never earned and a history the new identity was not part of;
        // deleting would throw away the user's own messages. It is marked
        // vanished, and the new identity arrives beside it as its own contact.
        // `!stale.isBlocked` matters as much as `!stale.isVanished`: a blocked
        // contact is absent from `serverIDs` for a reason the user chose, and
        // marking it vanished would tell them their own block was an identity
        // change — copy that reads as an impersonation warning.
        for stale in sameName
        where !stale.isPending && !stale.isVanished && !stale.isBlocked
              && !serverIDs.contains(stale.peerID) {
            stale.vanishedAt = Date()
            dlog("[DirectorySync] ⚠️ \(username)'s identity changed — \(stale.peerID.prefix(8))… "
                 + "is gone, \(id.prefix(8))… is new")
        }

        let friend = Friend(username: username, peerID: id,
                            isOnline: false,
                            inviteStatus: status, profile: currentProfile)
        modelContext.insert(friend)
        dlog("[DirectorySync] ✅ added \(username)")
        return friend
    }

    /// An accepted friendship never regresses to "invite received" because a
    /// stale invite row is still listed.
    private func advance(_ friend: Friend, to status: Friend.InviteStatus) {
        if friend.inviteStatus == .accepted { return }
        friend.inviteStatus = status
    }

    /// Adopt the server's block list, in both directions.
    ///
    /// The user may have blocked somebody from another device, and may have
    /// unblocked them there too. Both have to arrive, and the first one has to
    /// arrive BEFORE `reconcileRemovals` runs — which is why this is a separate
    /// pass rather than something folded into `upsert`: a blocked peer is not in
    /// `/friends`, so `upsert` is never called for them at all.
    // Not `private`: OrchestratorTests drives both reconcile passes directly.
    // The alternative is testing a history-destroying deletion only through a
    // full HTTP round trip, which is the kind of coverage that quietly stops
    // existing.
    func reconcileBlocks(blockedIDs: Set<String>, profileId: UUID) {
        let all = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.profile?.id == profileId }
        )
        guard let rows = try? modelContext.fetch(all) else { return }
        for row in rows where !row.isPending {
            let blocked = blockedIDs.contains(row.peerID)
            if blocked && !row.isBlocked {
                row.blockedAt = Date()
                dlog("[DirectorySync] 🚫 \(row.username) is blocked (from another device)")
            } else if !blocked && row.isBlocked {
                row.blockedAt = nil
                dlog("[DirectorySync] ✅ \(row.username) is no longer blocked")
            }
        }
    }

    /// Drop local rows the server no longer knows about: an unfriend from the
    /// other side, or an invite that was withdrawn/declined.
    func reconcileRemovals(serverIDs: Set<String>, profileId: UUID) {
        let all = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.profile?.id == profileId }
        )
        guard let rows = try? modelContext.fetch(all) else { return }
        for row in rows {
            // Rows still waiting on an id (an invite we just sent) are ours, not
            // the server's, and must survive a sync.
            if row.isPending { continue }
            if serverIDs.contains(row.peerID) { continue }
            if row.inviteStatus == .inviteSent { continue }
            // A vanished identity is ALREADY absent from the server — that is
            // what vanished means. Deleting it here would undo the whole point:
            // the history is kept, read-only, and only the user removes it.
            if row.isVanished { continue }
            // Same reasoning, different cause. A blocked contact is absent
            // because the user made them absent; deleting the conversation they
            // blocked someone over is the opposite of what they asked for.
            // Unblocking clears the flag and this row becomes ordinary again —
            // at which point, still absent from the directory, it is removed.
            if row.isBlocked { continue }
            dlog("[DirectorySync] 🗑️ \(row.username) no longer on the server — removing")
            row.clearAESKeys()          // purge Keychain key material
            modelContext.delete(row)
        }
    }
}
