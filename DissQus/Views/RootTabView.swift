//
//  RootTabView.swift
//  DissQus
//
//  iPhone shell: a bottom tab bar replacing the old "…" toolbar menu.
//
//  macOS keeps `FriendListView`'s NavigationSplitView + profile rail — a tab bar
//  is the wrong shape for a desktop window, and the split view is right there.
//

#if os(iOS)
import SwiftUI
import SwiftData

struct RootTabView: View {
    @Environment(\.modelContext) private var modelContext
    @EnvironmentObject var appState: AppState

    let session: ChatSession
    let profileManager: ProfileManager?

    /// Owned here and passed down, rather than constructed per-tab. Two tabs
    /// each building their own `FriendService` would repeat the bug that made
    /// newly created profiles invisible until relaunch.
    @StateObject private var friendService: FriendService
    @ObservedObject var userService: UserService
    @ObservedObject private var notifications = NotificationService.shared

    /// The selection lives on `AppState` (as `AppTab`), not here: the
    /// "username taken" banner that switches to Settings sits at the root now,
    /// above this view, and cannot reach `@State` declared inside it.
    private var tab: Binding<AppTab> { $appState.selectedTab }

    init(session: ChatSession,
         userService: UserService,
         profileManager: ProfileManager? = nil) {
        self.session = session
        self.profileManager = profileManager
        self.userService = userService
        _friendService = StateObject(wrappedValue: FriendService(
            session: session, profileManager: profileManager))
    }

    // The "username taken" banner that used to sit here is now
    // `AppStatusBanners`, rendered once at the root so macOS gets it too.
    var body: some View {
        TabView(selection: tab) {
            ChatListView(
                session: session,
                friendService: friendService,
                profileManager: profileManager
            )
            .tabItem { Label("chats", systemImage: "bubble.left.and.bubble.right.fill") }
            .badge(notifications.unreadMessages)
            .tag(AppTab.chats)

            ContactsView(
                friendService: friendService,
                userService: userService,
                profileManager: profileManager
            )
            .tabItem { Label("contacts", systemImage: "person.2.fill") }
            .badge(notifications.pendingInvites)
            .tag(AppTab.contacts)

            SettingsView(userService: userService, profileManager: profileManager, isEmbedded: true)
                .tabItem { Label("settings", systemImage: "gearshape.fill") }
                .tag(AppTab.settings)
        }
        .tint(HQColor.green)
        // Swipe left/right between the three tabs. The tab bar is still the
        // primary control; this just means a thumb already resting on the
        // content doesn't have to travel to the bottom of the screen.
        .hqSwipeNavigation(onBack: { move(-1) }, onForward: { move(1) })
        .onAppear {
            friendService.setModelContext(modelContext)
            if let profileManager {
                friendService.setProfileManager(profileManager)
            }
            // Badges have to be right on a cold launch too, not only after
            // something arrives while we're watching.
            notifications.refreshCounts(modelContext: modelContext,
                                        profileID: profileManager?.currentProfile?.id)
            Task { await refreshAll() }
        }
    }

    /// Step `delta` tabs along, stopping at the ends rather than wrapping —
    /// wrapping from settings back to chats would make the gesture feel like it
    /// had lost its place.
    private func move(_ delta: Int) {
        guard let i = AppTab.ordered.firstIndex(of: appState.selectedTab) else { return }
        let next = i + delta
        guard AppTab.ordered.indices.contains(next) else { return }
        withAnimation(.easeOut(duration: 0.2)) { appState.selectedTab = AppTab.ordered[next] }
    }

    /// Friends *and* invites. The old menu-item refresh only asked for friends,
    /// which is why pending invites looked stale until the app restarted.
    private func refreshAll() async {
        try? await friendService.requestFriendsList()
        try? await friendService.requestInvitesList()
    }
}
#endif
