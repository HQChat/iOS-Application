//
//  ChatListView.swift
//  DissQus
//
//  The Chats tab: conversations only. Contacts and invites live in their own
//  tab, so this list stops mixing three jobs into one screen.
//

#if os(iOS)
import SwiftUI
import SwiftData

struct ChatListView: View {
    @Environment(\.modelContext) private var modelContext
    @EnvironmentObject var appState: AppState
    /// Message previews are sealed at rest. Observing the gate re-renders them
    /// the moment the single unlock lands; asking here means the prompt happens
    /// when a screen that shows bodies appears, never from a view body.
    @ObservedObject private var messageKeys = MessageKeyGate.shared
    @Query(sort: \Friend.username) private var allFriends: [Friend]

    let session: ChatSession
    @ObservedObject var friendService: FriendService
    let profileManager: ProfileManager?

    /// Navigation path, so a demo/screenshot run can open a conversation
    /// without a tap. This used to be a `selectedFriend` state nothing read —
    /// the deep-link had been dead since the list moved to value-based links.
    @State private var path = NavigationPath()
    @State private var appError: AppError?

    /// Only established contacts get a conversation. Pending invites can't be
    /// messaged — they have no secure channel yet — so showing them here would
    /// just be a row that fails when tapped.
    private var conversations: [Friend] {
        guard let currentProfile = profileManager?.currentProfile else { return [] }
        return allFriends
            .filter { $0.profile?.id == currentProfile.id && $0.inviteStatus == .accepted }
            // Most recently active first. Alphabetical is right for a contact
            // list and wrong for a conversation list — the thread you just
            // replied to should not be three screens down because of its name.
            .sorted { lastActivity($0) > lastActivity($1) }
    }

    /// When this conversation last moved. Never-used threads sort to the bottom
    /// but keep a stable order among themselves.
    private func lastActivity(_ friend: Friend) -> Date {
        (friend.messages ?? []).map(\.timestamp).max() ?? .distantPast
    }

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                HQScreenHeader(path: "chats", appState: appState, profileManager: profileManager)

                if conversations.isEmpty {
                    HQEmptyState(
                        title: "no conversations yet",
                        message: "add someone in Contacts to start messaging securely"
                    )
                    .frame(maxHeight: .infinity)
                } else {
                    List(conversations) { friend in
                        NavigationLink(value: friend) {
                            ContactRow(friend: friend, style: .conversation)
                        }
                        .listRowBackground(Color.clear)
                        .padding(.vertical, 4)
                    }
                    .scrollContentBackground(.hidden)
                    .refreshable { try? await friendService.requestFriendsList() }
                }
            }
            .background(HQScreenBackground())
            // The prompt header names the screen; a system title on top of it
            // would say it twice, in a different voice.
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: Friend.self) { friend in
                ChatView(friend: friend,
                         session: session,
                         profileManager: profileManager)
            }
            .hqError($appError)
            .onAppear {
                // Demo: deep-link straight into a conversation to showcase chat.
                if PersistenceController.isDemo, path.isEmpty,
                   ProcessInfo.processInfo.environment["DEMO_CHAT"] == "1",
                   let friend = conversations.first(where: { !($0.messages?.isEmpty ?? true) })
                        ?? conversations.first {
                    path.append(friend)
                }
            }
            // One prompt, here, for every preview on the list. Asking from a
            // screen's `task` rather than from a row keeps authentication off
            // the render path entirely.
            .task { await messageKeys.unlock() }
        }
    }
}
#endif
