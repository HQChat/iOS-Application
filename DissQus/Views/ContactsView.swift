//
//  ContactsView.swift
//  DissQus
//
//  The Contacts tab: pending invites, established contacts, and adding someone
//  new — all in one place instead of split between a toolbar button, an
//  empty-state button, and a modal sheet.
//

#if os(iOS)
import SwiftUI
import SwiftData

struct ContactsView: View {
    @Environment(\.modelContext) private var modelContext
    @EnvironmentObject var appState: AppState
    @Query(sort: \Friend.username) private var allFriends: [Friend]

    @ObservedObject var friendService: FriendService
    @ObservedObject var userService: UserService
    let profileManager: ProfileManager?

    @State private var path = NavigationPath()
    @State private var appError: AppError?
    @State private var friendToRemove: Friend?
    @State private var showingRemoveConfirmation = false
    @State private var friendToBlock: Friend?
    @State private var showingBlockConfirmation = false

    private var scoped: [Friend] {
        guard let currentProfile = profileManager?.currentProfile else { return [] }
        return allFriends.filter { $0.profile?.id == currentProfile.id }
    }

    private var incoming: [Friend] { scoped.filter { $0.inviteStatus == .inviteReceived } }
    private var outgoing: [Friend] { scoped.filter { $0.inviteStatus == .inviteSent } }
    private var accepted: [Friend] { scoped.filter { $0.inviteStatus == .accepted } }
    /// Contacts whose identity is gone. Listed separately so a read-only history
    /// is not sitting in the middle of the people you can actually write to.
    private var vanished: [Friend] { accepted.filter(\.isVanished) }
    /// Contacts the user blocked. Listed separately for the same reason vanished
    /// ones are: a read-only history has no business sitting among the people you
    /// can actually write to. Unlike a vanished identity, this one is the user's
    /// own decision and the user can undo it.
    private var blocked: [Friend] { scoped.filter(\.isBlocked) }
    private var reachable: [Friend] { accepted.filter { !$0.isVanished && !$0.isBlocked } }

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                HQScreenHeader(path: "contacts", appState: appState, profileManager: profileManager)

                // The macOS friend list has said this since the paywall landed;
                // this tab — the iPhone's equivalent surface — said nothing, so
                // a free user met the gate only as a sheet, after tapping.

                if scoped.isEmpty {
                    HQEmptyState(
                        title: "no contacts yet",
                        message: "add someone by their username to start messaging securely"
                    )
                    .frame(maxHeight: .infinity)
                } else {
                    List {
                        if !incoming.isEmpty {
                            Section(header: HQFieldLabel(text: "wants to connect")) {
                                ForEach(incoming) { friend in
                                    ContactRow(friend: friend,
                                               onAccept: { accept(friend) },
                                               onCancel: { cancel(friend) })
                                        .listRowBackground(Color.clear)
                                }
                            }
                        }

                        if !outgoing.isEmpty {
                            Section(header: HQFieldLabel(text: "invites you sent")) {
                                ForEach(outgoing) { friend in
                                    ContactRow(friend: friend, onCancel: { cancel(friend) })
                                        .listRowBackground(Color.clear)
                                }
                            }
                        }

                        if !reachable.isEmpty {
                            Section(header: HQFieldLabel(text: "contacts")) {
                                ForEach(reachable) { friend in
                                    ContactRow(friend: friend)
                                        .listRowBackground(Color.clear)
                                        .swipeActions(edge: .trailing) {
                                            // Removal used to be long-press only,
                                            // which nothing on screen hinted at.
                                            Button(role: .destructive) {
                                                friendToRemove = friend
                                                showingRemoveConfirmation = true
                                            } label: {
                                                Label("Remove", systemImage: "person.crop.circle.badge.minus")
                                            }
                                            // Beside Remove rather than in a
                                            // sibling component: the design
                                            // system says extend what exists.
                                            Button {
                                                friendToBlock = friend
                                                showingBlockConfirmation = true
                                            } label: {
                                                Label("Block", systemImage: "hand.raised")
                                            }
                                            .tint(HQColor.warning)
                                        }
                                }
                            }
                        }

                        // People the user blocked. Their history is kept and
                        // read-only; the block itself lives on the server, so it
                        // holds across devices and across a re-invite.
                        if !blocked.isEmpty {
                            Section(header: HQFieldLabel(text: "blocked")) {
                                ForEach(blocked) { friend in
                                    ContactRow(friend: friend)
                                        .listRowBackground(Color.clear)
                                        .swipeActions(edge: .trailing) {
                                            Button {
                                                unblock(friend)
                                            } label: {
                                                Label("Unblock", systemImage: "hand.raised.slash")
                                            }
                                            .tint(HQColor.green)
                                        }
                                }
                            }
                        }

                        // Identities that no longer exist: the person re-keyed
                        // (reinstall, account reset, a new device) and their new
                        // identity is a separate contact above. Kept because the
                        // messages are the user's, and read-only because there is
                        // no key to encapsulate to and no topic anyone holds a
                        // grant on.
                        if !vanished.isEmpty {
                            Section(header: HQFieldLabel(text: "identities that are gone")) {
                                ForEach(vanished) { friend in
                                    ContactRow(friend: friend)
                                        .listRowBackground(Color.clear)
                                        .swipeActions(edge: .trailing) {
                                            Button(role: .destructive) {
                                                friendToRemove = friend
                                                showingRemoveConfirmation = true
                                            } label: {
                                                Label("Delete", systemImage: "trash")
                                            }
                                        }
                                }
                            }
                        }
                    }
                    .scrollContentBackground(.hidden)
                    .refreshable { await refreshAll() }
                }

                // Bottom of the screen, within thumb reach and out of the way of
                // the list — a primary action shouldn't sit at the top edge on a
                // phone, and it shouldn't push the contacts down either.
                Button { path.append(Route.add) } label: {
                    HStack(spacing: 8) {
                        Text("[+]").font(HQFont.mono(14, weight: .heavy))
                        Text("add contact")
                    }
                }
                .buttonStyle(HQPrimaryButtonStyle(height: 46))
                .accessibilityLabel("add contact")
                .padding(.horizontal, 16)
                .padding(.top, 10)
                .padding(.bottom, 16)
            }
            .background(HQScreenBackground())
            // No `.navigationTitle("Contacts")`: the prompt header already names
            // the screen, and the list's own "contacts" section said it twice.
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: Route.self) { _ in
                AddContactView(friendService: friendService, userService: userService,
                               pendingUsernames: Set(outgoing.map(\.username)),
                               // Vanished identities excluded: their handle
                               // belongs to whoever holds it now, and reporting
                               // "already added" would leave the user unable to
                               // add the contact they can actually reach.
                               contactUsernames: Set(accepted.filter { !$0.isVanished }.map(\.username)),
                               incomingUsernames: Set(incoming.map(\.username)),
                               myUsername: userService.currentUsername)
            }
            .hqError($appError)
            .alert("Remove contact", isPresented: $showingRemoveConfirmation) {
                Button("Cancel", role: .cancel) { friendToRemove = nil }
                Button("Remove", role: .destructive) {
                    if let friend = friendToRemove { remove(friend) }
                }
            } message: {
                if let friend = friendToRemove {
                    // A vanished identity has no friendship left to end — the
                    // person is already unreachable under it — so what is being
                    // decided is only whether to keep the history.
                    Text(friend.isVanished
                         ? "Delete this conversation with \(friend.username)? It's with an identity that no longer exists, so nothing is unfriended — the messages are just removed from this device."
                         : "Remove \(friend.username)? Your conversation and shared keys are deleted from this device.")
                }
            }
            // `.alert`, not `.confirmationDialog` — on iOS 26 a
            // confirmationDialog's cancel action never reaches the hierarchy.
            // The reason is recorded at AccountSettingsView.swift:70.
            .alert("Block contact", isPresented: $showingBlockConfirmation) {
                Button("Cancel", role: .cancel) { friendToBlock = nil }
                Button("Block", role: .destructive) {
                    if let friend = friendToBlock { block(friend) }
                }
            } message: {
                if let friend = friendToBlock {
                    Text("Block \(friend.username)? They can no longer reach you and cannot add you again. Your conversation stays on this device, read-only, and you can unblock them later.")
                }
            }
        }
    }

    /// Single navigation destination for this tab.
    private enum Route: Hashable { case add }

    // MARK: - Actions

    private func accept(_ friend: Friend) {
        Task {
            do { try await friendService.acceptInvite(username: friend.username) }
            catch { appError = .from(error) }
        }
    }

    private func cancel(_ friend: Friend) {
        Task {
            do { try await friendService.cancelInvite(username: friend.username) }
            catch { appError = .from(error) }
        }
    }

    private func remove(_ friend: Friend) {
        friendToRemove = nil
        Task {
            // By ROW, not by username: after an identity change two rows share a
            // handle, and resolving the handle server-side would unfriend the
            // live contact while deleting the dead one.
            do { try await friendService.remove(friend: friend) }
            catch { appError = .from(error) }
        }
    }

    private func block(_ friend: Friend) {
        friendToBlock = nil
        Task {
            do { try await friendService.block(friend: friend) }
            catch { appError = .from(error) }
        }
    }

    private func unblock(_ friend: Friend) {
        Task {
            do { try await friendService.unblock(friend: friend) }
            catch { appError = .from(error) }
        }
    }

    private func refreshAll() async {
        try? await friendService.requestFriendsList()
        try? await friendService.requestInvitesList()
    }

    // `requiresPayment()` stood here, opening the upgrade prompt before an
    // accept could go through. Adding contacts is not something anyone pays
    // for now, so the action is unconditional.
}
#endif
