//
//  FriendListView.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import SwiftUI
import SwiftData

struct FriendListView: View {
    @Environment(\.modelContext) private var modelContext
    @EnvironmentObject var appState: AppState
    @Query(sort: \Friend.username) private var allFriends: [Friend]
    
    @StateObject private var friendService: FriendService
    @StateObject private var userService: UserService
    @State private var newFriendUsername = ""
    @State private var showingAddFriend = false
    @State private var selectedFriend: Friend?
    @State private var errorMessage: String?
    @State private var searchText = ""
    @State private var friendToRemove: Friend?
    @State private var showingRemoveConfirmation = false
    @State private var showingServerInfo = false
    
    let session: ChatSession
    let profileManager: ProfileManager?
    
    // Filter friends by current profile
    private var friends: [Friend] {
        guard let currentProfile = profileManager?.currentProfile else {
            return []
        }
        return allFriends.filter { $0.profile?.id == currentProfile.id }
    }
    
    init(session: ChatSession, userService: UserService, profileManager: ProfileManager? = nil) {
        self.session = session
        self.profileManager = profileManager
        _friendService = StateObject(wrappedValue: FriendService(session: session, profileManager: profileManager))
        _userService = StateObject(wrappedValue: userService)
    }
    
    // Filtered users based on search
    private var filteredUsers: [UserListItem] {
        if searchText.isEmpty {
            return userService.userDirectory
        }
        return userService.userDirectory.filter { user in
            user.username.localizedCaseInsensitiveContains(searchText) ||
            user.id.localizedCaseInsensitiveContains(searchText)
        }
    }
    
    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                // Shared with the iOS Contacts tab (StatusPresentation.swift),
                // which had no equivalent at all until it was extracted.
                
                // Search Bar
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(HQColor.textMuted)

                    TextField("search users…", text: $searchText)
                        .textFieldStyle(.plain)
                        .foregroundColor(HQColor.textPrimary)

                    if !searchText.isEmpty {
                        Button {
                            searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(HQColor.textMuted)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .background(HQColor.fillSoft)
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.white.opacity(0.1), lineWidth: 1))
                .clipShape(RoundedRectangle(cornerRadius: 4))
                .padding(.horizontal)
                .padding(.bottom, 8)
                
                // Search Results or Friends List
                Group {
                    if !searchText.isEmpty {
                        // Show filtered users
                        List(filteredUsers, id: \.username) { user in
                            HStack(spacing: 12) {
                                HQAvatar(name: user.username, size: 40, glow: HQColor.purple)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("@\(user.username)")
                                        .font(HQFont.ui(15, weight: .semibold))
                                        .foregroundColor(HQColor.textPrimary)
                                    Text("id \(user.id.prefix(5))…")
                                        .font(HQFont.mono(11))
                                        .foregroundColor(HQColor.textFaint)
                                        .lineLimit(1)
                                }

                                Spacer()

                                Button {
                                    newFriendUsername = user.username
                                    showingAddFriend = true
                                } label: {
                                    Image(systemName: "person.badge.plus")
                                        .font(.system(size: 15))
                                        .foregroundColor(HQColor.green)
                                        .frame(width: 34, height: 34)
                                        .background(HQColor.green.opacity(0.08))
                                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(HQColor.green.opacity(0.4), lineWidth: 1))
                                        .clipShape(RoundedRectangle(cornerRadius: 3))
                                }
                                .buttonStyle(.plain)
                            }
                            .listRowBackground(Color.clear)
                            .padding(.vertical, 4)
                        }
                        .scrollContentBackground(.hidden)
                        .overlay {
                            if filteredUsers.isEmpty {
                                HQEmptyState(
                                    title: "no users found",
                                    message: "usernames must match exactly — check the spelling",
                                    systemImage: "magnifyingglass"
                                )
                            }
                        }
                    } else {
                    // Friends List
                    if friends.isEmpty {
                        HQEmptyState(
                            title: "no friends yet",
                            message: "add friends to start messaging securely",
                            actionTitle: "add friend",
                            action: { showingAddFriend = true }
                        )
                    } else {
                        List(friends, selection: $selectedFriend) { friend in
                            NavigationLink(value: friend) {
                                HStack(spacing: 12) {
                                    HQAvatar(name: friend.username, size: 44,
                                             glow: HQColor.purple, isOnline: friend.isOnline)

                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(friend.username)
                                            .font(HQFont.ui(16, weight: .semibold))
                                            .foregroundColor(HQColor.textPrimary)

                                        if friend.inviteStatus == .inviteSent {
                                            Text("invite sent")
                                                .font(HQFont.mono(11.5, weight: .medium))
                                                .foregroundColor(HQColor.warning)
                                        } else if friend.inviteStatus == .inviteReceived {
                                            Text("invite received")
                                                .font(HQFont.mono(11.5, weight: .medium))
                                                .foregroundColor(HQColor.purpleLight)
                                        } else if friend.isVanished {
                                            // The identity is gone: this contact
                                            // re-keyed, so the row is history and
                                            // nothing can be sent to it. It used
                                            // to render as an ordinary offline
                                            // contact — key-change state was
                                            // visible only after opening the
                                            // thread.
                                            HStack(spacing: 5) {
                                                Image(systemName: "exclamationmark.triangle.fill")
                                                    .font(.system(size: 9))
                                                Text("identity gone")
                                            }
                                            .font(HQFont.mono(11.5, weight: .medium))
                                            .foregroundColor(HQColor.warning)
                                        } else {
                                            HStack(spacing: 5) {
                                                Text(friend.isOnline ? "live" : "offline")
                                                    .foregroundColor(friend.isOnline ? HQColor.green : HQColor.textMuted)
                                                if friend.hasSession {
                                                    Text("· e2e").foregroundColor(HQColor.green)
                                                } else if !friend.hasPinnedKey {
                                                    Text("· awaiting key").foregroundColor(HQColor.textDim)
                                                }
                                            }
                                            .font(HQFont.mono(11.5, weight: .medium))
                                        }
                                    }

                                    Spacer()

                                    // Accept button for received invites
                                    if friend.inviteStatus == .inviteReceived {
                                        Button {
                                            Task {
                                                do {
                                                    try await friendService.acceptInvite(username: friend.username)
                                                } catch {
                                                    errorMessage = error.localizedDescription
                                                }
                                            }
                                        } label: {
                                            Text("accept")
                                                .font(HQFont.ui(13, weight: .semibold))
                                                .foregroundColor(HQColor.onGreen)
                                                .padding(.horizontal, 14).padding(.vertical, 7)
                                                .background(LinearGradient(colors: [HQColor.greenBright, HQColor.greenDeep],
                                                                           startPoint: .topLeading, endPoint: .bottomTrailing))
                                                .clipShape(RoundedRectangle(cornerRadius: 3))
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                            }
                            .listRowBackground(Color.clear)
                            .padding(.vertical, 4)
                            .contextMenu {
                                // Only show remove option for accepted friends (not pending invites)
                                if friend.inviteStatus == .accepted {
                                    Button(role: .destructive) {
                                        friendToRemove = friend
                                        showingRemoveConfirmation = true
                                    } label: {
                                        Label("Remove Friend", systemImage: "person.crop.circle.badge.minus")
                                    }
                                }
                            }
                        }
                        .scrollContentBackground(.hidden)
                    }
                }
                }
                .background(HQScreenBackground())
                .navigationTitle(searchText.isEmpty ? "Friends" : "Search Users")
                .toolbar {
                    #if os(iOS)
                    // Left: server glyph — green when connected, grey otherwise. Tap for details.
                    ToolbarItem(placement: .topBarLeading) {
                        ServerInfoButton(appState: appState) {
                            showingServerInfo = true
                        }
                    }
                    #else
                    ToolbarItem(placement: .primaryAction) {
                        ConnectionStatusButton(appState: appState)
                    }
                    #endif
                    // Right: Add Friend as a direct, clearly-clickable action.
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            showingAddFriend = true
                        } label: {
                            Label("Add Friend", systemImage: "person.badge.plus")
                        }
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Menu {
                            #if os(iOS)
                            Button {
                                appState.showingProfileSwitcher = true
                            } label: {
                                Label("Switch Profile", systemImage: "person.crop.circle.badge.checkmark")
                            }
                            #endif

                            Button {
                                appState.showingSettings = true
                            } label: {
                                Label("Settings", systemImage: "gearshape")
                            }

                            Divider()

                            Button {
                                Task {
                                    try? await friendService.requestFriendsList()
                                }
                            } label: {
                                Label("Refresh", systemImage: "arrow.clockwise")
                            }
                        } label: {
                            Image(systemName: "ellipsis.circle")
                        }
                    }
                }
            }
        } detail: {
            if let friend = selectedFriend {
                ChatView(friend: friend, session: session, profileManager: profileManager)
            } else {
                VStack(spacing: 14) {
                    HQLogoMark(size: 64)
                    Text("select a conversation")
                        .font(HQFont.ui(15, weight: .semibold))
                        .foregroundColor(HQColor.textSecond)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .hqScreenBackground()
            }
        }
        .onAppear {
            if PersistenceController.isDemo, ProcessInfo.processInfo.environment["DEMO_SETTINGS"] == "1" {
                appState.showingSettings = true
            }
            // Demo: deep-link straight into a conversation to showcase chat.
            if PersistenceController.isDemo, selectedFriend == nil,
               ProcessInfo.processInfo.environment["DEMO_NO_CHAT"] != "1",
               ProcessInfo.processInfo.environment["DEMO_SETTINGS"] != "1" {
                selectedFriend = friends.first { !($0.messages?.isEmpty ?? true) } ?? friends.first
            }
        }
        .sheet(isPresented: $appState.showingSettings) {
            SettingsView(userService: userService, profileManager: profileManager)
                .environmentObject(appState)
        }
        .sheet(isPresented: $showingServerInfo) {
            ServerInfoView(
                appState: appState,
                serverURL: ServerConfig.apiBaseURL
            )
        }
        .sheet(isPresented: $showingAddFriend) {
            AddFriendSheet(
                username: $newFriendUsername,
                onAdd: { username in
                    Task {
                        do {
                            try await friendService.sendFriendRequest(username: username)
                            newFriendUsername = ""
                            showingAddFriend = false
                        } catch {
                            errorMessage = error.localizedDescription
                        }
                    }
                }
            )
        }
        .alert("Error", isPresented: .constant(errorMessage != nil)) {
            Button("OK") {
                errorMessage = nil
            }
        } message: {
            if let error = errorMessage {
                Text(error)
            }
        }
        .alert("Remove Friend", isPresented: $showingRemoveConfirmation) {
            Button("Cancel", role: .cancel) {
                friendToRemove = nil
            }
            Button("Remove", role: .destructive) {
                if let friend = friendToRemove {
                    Task {
                        do {
                            // By ROW: after an identity change two rows share a
                            // handle, and resolving it server-side would unfriend
                            // the live contact while deleting the dead one.
                            try await friendService.remove(friend: friend)
                            friendToRemove = nil
                            // Deselect if the removed friend was selected
                            if selectedFriend?.username == friend.username {
                                selectedFriend = nil
                            }
                        } catch {
                            errorMessage = error.localizedDescription
                            friendToRemove = nil
                        }
                    }
                }
            }
        } message: {
            if let friend = friendToRemove {
                Text("Are you sure you want to remove \(friend.username) from your friends list?")
            }
        }
        .onAppear {
            // Update friendService with actual modelContext and profileManager
            friendService.setModelContext(modelContext)
            if let profileManager = profileManager {
                friendService.setProfileManager(profileManager)
            }
            Task {
                try? await friendService.requestFriendsList()
            }
        }
        .onChange(of: searchText) { oldValue, newValue in
            // The server does exact-username lookup now (no bulk directory), so
            // query it as the user types.
            Task { try? await userService.searchUsers(query: newValue) }
        }
    }
}

struct AddFriendSheet: View {
    @Binding var username: String
    let onAdd: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    PlainUsernameField(placeholder: "Username", text: $username)
                } header: {
                    Text("Friend's username")
                } footer: {
                    Text("They'll receive an invite to connect securely.")
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Add Friend")
            .inlineNavTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        if !username.isEmpty { onAdd(username); dismiss() }
                    }
                    .disabled(username.isEmpty)
                }
            }
        }
        .sheetSizing()
    }
}

#Preview {
    let container = try! ModelContainer(for: Friend.self, Message.self)
    let session = ChatSession()
    let userService = UserService(api: session.api)

    return FriendListView(session: session, userService: userService)
        .modelContainer(container)
}


/// Circular avatar showing a contact's initials over a deterministic gradient,
/// with an optional online presence dot. Shared across the friend list and chat.
struct InitialsAvatar: View {
    let name: String
    var isOnline: Bool? = nil
    var size: CGFloat = 44

    private var initials: String {
        let parts = name
            .replacingOccurrences(of: "_", with: " ")
            .replacingOccurrences(of: ".", with: " ")
            .split(separator: " ")
        let letters = parts.prefix(2).compactMap { $0.first }
        let result = String(letters).uppercased()
        return result.isEmpty ? "?" : result
    }

    private var gradient: LinearGradient {
        let palette: [[Color]] = [
            [.blue, .cyan], [.purple, .indigo], [.pink, .orange],
            [.green, .teal], [.orange, .red], [.mint, .blue]
        ]
        let idx = abs(name.hashValue) % palette.count
        return LinearGradient(colors: palette[idx], startPoint: .topLeading, endPoint: .bottomTrailing)
    }

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            Circle()
                .fill(gradient)
                .frame(width: size, height: size)
                .overlay(
                    Text(initials)
                        .font(.system(size: size * 0.4, weight: .semibold))
                        .foregroundColor(.white)
                )

            if let isOnline {
                Circle()
                    .fill(isOnline ? Color.green : Color.gray)
                    .frame(width: size * 0.28, height: size * 0.28)
                    .overlay(Circle().stroke(Color.windowBackground, lineWidth: 2))
            }
        }
    }
}

// MARK: - Cross-platform sheet helpers

extension View {
    /// Inline navigation-bar title on iOS; no-op on macOS.
    @ViewBuilder func inlineNavTitle() -> some View {
        #if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }

    /// A sensible default size for sheets on macOS; iOS uses the system sheet.
    @ViewBuilder func sheetSizing(minWidth: CGFloat = 380, minHeight: CGFloat = 240) -> some View {
        #if os(macOS)
        self.frame(minWidth: minWidth, minHeight: minHeight)
        #else
        self
        #endif
    }
}

/// Text field tuned for usernames (no autocapitalization/autocorrect on iOS).
struct PlainUsernameField: View {
    let placeholder: String
    @Binding var text: String

    var body: some View {
        #if os(iOS)
        TextField(placeholder, text: $text)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
        #else
        TextField(placeholder, text: $text)
        #endif
    }
}
