//
//  AddContactView.swift
//  DissQus
//
//  Adding a contact, in one screen and one tap.
//
//  It used to take two: a search field fired a server lookup on every keystroke,
//  and the "+" on a result only pre-filled a modal sheet that you then had to
//  submit. The sheet had its own separate entry point too.
//

#if os(iOS)
import SwiftUI

struct AddContactView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @ObservedObject var friendService: FriendService
    @ObservedObject var userService: UserService
    /// Usernames with an invite already outstanding, so the row can say so
    /// instead of offering to invite them twice.
    let pendingUsernames: Set<String>
    /// Usernames that are already contacts. Searching for someone you added
    /// last week used to look exactly like searching for a stranger.
    let contactUsernames: Set<String>
    /// Invites waiting on *you* — accepting them belongs in Contacts.
    let incomingUsernames: Set<String>
    /// Your own handle, so you can't invite yourself.
    let myUsername: String?

    @State private var query = ""
    @State private var appError: AppError?
    @State private var searchTask: Task<Void, Never>?
    @State private var isSearching = false
    @State private var justInvited: Set<String> = []

    /// The server does exact-username lookup only (bulk directory listing was
    /// removed for privacy), so there is nothing to filter client-side.
    private var results: [UserListItem] { userService.userDirectory }

    /// How a result already relates to you — the row uses this instead of
    /// offering an add button unconditionally.
    private func relation(for username: String) -> ContactRelation {
        if let mine = myUsername, mine.caseInsensitiveCompare(username) == .orderedSame { return .you }
        if contactUsernames.contains(username) { return .added }
        if incomingUsernames.contains(username) { return .awaitingYou }
        if pendingUsernames.contains(username) || justInvited.contains(username) { return .invited }
        return .none
    }

    var body: some View {
        VStack(spacing: 0) {
            HQSubScreenHeader(path: "contacts/add") { dismiss() }
            searchField

            if query.isEmpty {
                HQEmptyState(
                    title: "find someone",
                    message: "type their exact username — usernames aren't browsable, by design",
                    systemImage: "at"
                )
            } else if let reason = UsernameRule.rejectionReason(query) {
                // Same rule the server enforces, applied before anything is sent:
                // a handle that can't exist never becomes a lookup.
                HQEmptyState(
                    title: reason,
                    message: UsernameRule.hint,
                    systemImage: "exclamationmark.triangle"
                )
            } else if isSearching {
                LoadingView(message: "searching…")
            } else if results.isEmpty {
                HQEmptyState(
                    title: "no match",
                    message: "no account uses that username — check the spelling",
                    systemImage: "magnifyingglass"
                )
            } else {
                List(results, id: \.username) { user in
                    UserSearchRow(
                        user: user,
                        relation: relation(for: user.username),
                        onAdd: { invite(user) }
                    )
                    .listRowBackground(Color.clear)
                    .padding(.vertical, 4)
                }
                .scrollContentBackground(.hidden)
            }
        }
        .background(HQScreenBackground())
        // The prompt header above names the screen; a system nav bar on top of
        // it would say it twice, in a different voice.
        .toolbar(.hidden, for: .navigationBar)
        .hqError($appError)
        // Same way out as every other pushed screen, from anywhere on it.
        .hqSwipeNavigation(onBack: { dismiss() })
        .onDisappear { searchTask?.cancel() }
    }

    private var searchField: some View {
        HStack {
            Image(systemName: "at").foregroundColor(HQColor.textMuted)

            TextField("username", text: $query)
                .textFieldStyle(.plain)
                .foregroundColor(HQColor.textPrimary)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                // Filtering on input, not just validating on submit: nothing
                // outside the username alphabet can be typed or pasted here, so
                // no crafted string ever reaches the lookup.
                .onChange(of: query) { _, newValue in
                    let clean = UsernameRule.sanitized(newValue)
                    if clean != newValue { query = clean; return }
                    scheduleSearch(clean)
                }

            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill").foregroundColor(HQColor.textMuted)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(HQColor.fillSoft)
        .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.white.opacity(0.1), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 4))
        .padding()
    }

    /// Debounced lookup. The old screen sent a `get_users` frame on every single
    /// keystroke.
    private func scheduleSearch(_ text: String) {
        searchTask?.cancel()
        let trimmed = UsernameRule.normalized(text)
        guard UsernameRule.isValid(trimmed) else {
            isSearching = false
            return
        }
        isSearching = true
        searchTask = Task {
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard !Task.isCancelled else { return }
            try? await userService.searchUsers(query: trimmed)
            guard !Task.isCancelled else { return }
            isSearching = false
        }
    }

    private func invite(_ user: UserListItem) {
        // Belt and braces: the row only offers this in `.none`, but the guard
        // keeps a stale result from re-inviting an existing contact.
        guard relation(for: user.username) == .none else { return }
        // Mark optimistically so the row can't be tapped twice while in flight.
        justInvited.insert(user.username)
        Task {
            do {
                try await friendService.sendFriendRequest(username: user.username)
            } catch {
                justInvited.remove(user.username)
                appError = .from(error)
            }
        }
    }
}
#endif
