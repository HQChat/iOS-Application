//
//  AppState.swift
//  DissQus
//
//  Shared app state for macOS and iOS targets.
//

import SwiftUI
import SwiftData
import Foundation
#if os(iOS)
import UIKit
#endif

/// The iPhone tab bar's tabs. Declared out here rather than inside
/// `RootTabView` (which is `#if os(iOS)`) so `AppState` — a file both platforms
/// compile — can hold the selection.
enum AppTab: Hashable {
    case chats, contacts, settings

    /// Tabs in bar order, so a swipe moves the way the bar reads.
    static let ordered: [AppTab] = [.chats, .contacts, .settings]

    /// Lets a UI test (or a demo run) open straight onto a given tab:
    /// `SIMCTL_CHILD_DEMO_TAB=contacts`.
    static var initialFromEnvironment: AppTab {
        switch ProcessInfo.processInfo.environment["DEMO_TAB"] {
        case "contacts": return .contacts
        case "settings": return .settings
        default: return .chats
        }
    }
}

// App state manager
@MainActor
class AppState: ObservableObject {
    @Published var isAuthenticated = false
    /// Which door the handshake came back through. It no longer gates anything
    /// in the UI — every session gets the whole app — but it is still what the
    /// server minted, and a `free` scope against a private (`allowlist`) server
    /// is a real, diagnosable state rather than a paywall.
    @Published var scope: AuthService.Scope = .free
    /// The server refuses this key outright — an allowlist server. There is no
    /// longer any other kind of refusal.
    @Published var notAdmitted = false
    @Published var connectionError: String?
    /// App-level error channel, presented once at the root. Views with their own
    /// local failures still use their own `AppError` state; this is for things
    /// that arrive asynchronously (server ERROR frames, call failures) with no
    /// obvious owning screen.
    @Published var lastError: AppError?
    @Published var isConnecting = false
    @Published var connectionStatus: ConnectionStatus = .disconnected
    @Published var profileManager: ProfileManager?
    @Published var hasActiveProfile = false
    @Published var showingProfileSwitcher = false  // iOS: drives the profile-switch sheet
    /// macOS: drives `FriendListView`'s Settings sheet. Owned here, like the
    /// profile switcher above, because the status banners sit at the root now
    /// and cannot reach into the desktop shell's local state.
    @Published var showingSettings = false
    /// iOS: which tab the bottom bar shows. Owned here for the same reason —
    /// the root-level "username taken" banner sends people to Settings, and it
    /// lives above `RootTabView` rather than inside it.
    @Published var selectedTab: AppTab = AppTab.initialFromEnvironment
    /// A username the server refused because someone else owns it. Set from the
    /// error path and cleared when a handle is finally accepted; drives the
    /// banner that offers a way out.
    @Published var usernameRejected: String?

    /// What the server says about itself when it is mid-change, or nil.
    ///
    /// Set from `/info`. Advisory only — nothing keys off it but the banner,
    /// deliberately: a wire-version flip switches every contact at once and so
    /// happens in a window, and the window is exactly when a client most needs
    /// to reach the server rather than be locked out of it.
    @Published var maintenanceNotice: String?
    /// Set to push Settings → Account (the banner's "choose another" action).
    @Published var openAccountSettings = false

    /// Take the user to Settings → Account, from anywhere, on either platform.
    ///
    /// The two shells get there differently — iOS switches tab, macOS opens a
    /// sheet — and the caller (a banner at the root) knows about neither. That
    /// asymmetry is the whole reason this is a method and not a flag.
    func showAccountSettings() {
        #if os(iOS)
        selectedTab = .settings
        #else
        showingSettings = true
        #endif
        openAccountSettings = true
    }
    /// Profile whose keychain key access was already biometrically verified
    /// this session — prevents re-prompting Face ID on every initialize().
    private var unlockedProfileId: UUID?

    #if DEBUG
    /// The `UITEST_FRESH` wipe runs once per launch, not once per
    /// `initialize()` — which is called from several places.
    private static var didResetForUITest = false
    #endif

    /// Guards `initialize()` against re-entrancy. It is called from many
    /// onAppear/task sites; this flag serializes concurrent calls so a second
    /// run cannot reconfigure the session mid-handshake and drop the auth.
    private var isInitializing = false

    /// Profile the live socket last authenticated as. Used to detect a profile
    /// switch: connectToServer() early-returns while `.authenticated`, so
    /// without this the new profile inherits the old one's connection and
    /// broker subscriptions instead of re-authing.
    private var connectedProfileId: UUID?

    enum ConnectionStatus: Equatable {
        case disconnected
        case connecting
        case connected
        case authenticated
        case notAdmitted
        /// The device itself has no network path. Distinct from `.error`, which
        /// means we reached the network but not a working server.
        case offline
        case error(String)
    }

    /// True once the server has refused this key outright (403 — an `allowlist`
    /// deployment). While set, we stop the reconnect loop: the server has told
    /// us it will not have this key, so retrying only asks the same question.
    fileprivate var blocked = false

    /// The whole connection: REST for control, MQTT for messages and presence.
    /// There is no bespoke socket protocol any more (see ChatSession).
    let session = ChatSession()
    /// Device network path. Owned here (not created per-view) so every consumer
    /// observes the same instance.
    let reachability = Reachability()
    private var modelContext: ModelContext?

    init() {
        reachability.onBecameOnline = { [weak self] in
            guard let self else { return }
            print("[AppState] 📶 Network came back — waking reconnect")
            if case .offline = self.connectionStatus {
                self.connectionStatus = .connecting
            }
        }
    }


    // Reconnect state (exponential backoff, capped at 30s)
    @Published var isReconnecting = false
    fileprivate var reconnectAttempt = 0
    fileprivate var reconnectTask: Task<Void, Never>?
    private static let maxReconnectDelay: Double = 30.0
    /// How long to wait for the auth handshake after a socket reconnects.
    private static let authGrace: TimeInterval = 10.0
    @Published var userService: UserService?

    /// Going behind: publish presence "offline" so the push-bridge starts waking
    /// this device instead of assuming we can still receive. iOS freezes the
    /// socket rather than closing it, so without this explicit flip the broker
    /// keeps us online until keepalive lapses — and for that whole window
    /// messages arrive at a suspended app and no push is sent.
    func enterBackground() async {
        // A conversation on screen suppresses its own banners; once the app is
        // behind, nothing is on screen and every arrival should be announced.
        NotificationService.shared.isForeground = false
        guard isAuthenticated else { return }
        #if os(iOS)
        // Without an assertion, iOS can suspend us the moment the scene-phase
        // handler returns — and the packet that says "I am away" would be the
        // thing that never makes it out.
        //
        // The assertion has to outlive the WRITE, not the call. `setPresence`
        // used to return as soon as the publish was scheduled, so this released
        // the assertion while the frame was still in a dispatch queue; when iOS
        // won that race the broker kept us marked online and the push-bridge —
        // which wakes a device only when presence says it is offline, and decides
        // that once, per message, with no retry — stayed silent. It now returns
        // when the bytes have reached the socket.
        let task = await UIApplication.shared.beginBackgroundTask(withName: "hq.presence")
        let announced = await session.setPresence(online: false)
        if !announced {
            // Nothing more we can do from here: the socket was already gone, so
            // the broker's Last-Will is what will mark us offline, and messages
            // arriving before its keepalive lapses will not raise a push.
            print("[AppState] could not announce offline before suspending — relying on the Last-Will")
        }
        if task != .invalid { await UIApplication.shared.endBackgroundTask(task) }
        #else
        await session.setPresence(online: false)
        #endif
    }

    /// Back in front: re-announce presence and pull anything the graph missed.
    /// Messages that arrived while we were away are replayed by the broker (the
    /// MQTT session is persistent and QoS 1), so there is nothing to ask for.
    func enterForeground() async {
        NotificationService.shared.isForeground = true
        guard isAuthenticated else { return }
        guard session.isConnected else {
            // The link did not survive the background. Treat it as what it is —
            // a dropped connection — rather than leaving the app believing it is
            // authenticated on a socket that is gone.
            print("[AppState] link is gone on foreground — reconnecting")
            isAuthenticated = false
            connectionStatus = .disconnected
            await disconnectSession()
            return
        }
        await session.setPresence(online: true)
        await session.refreshDirectory()
    }

    /// Drop the in-memory key hold (unsecure mode). Called on background so the
    /// key isn't retained while the app is not in use.
    func clearCachedKey() {
        profileManager?.clearCachedKey()
    }

    func initialize() async {
        // Re-entrancy guard: serialize concurrent calls (see `isInitializing`).
        if isInitializing { return }
        isInitializing = true
        defer { isInitializing = false }

        // Set up model context (only if not already set)
        if modelContext == nil {
            let container = PersistenceController.shared.container
            modelContext = container.mainContext
        }
        
        // Initialize or reload profile manager
        if profileManager == nil {
            profileManager = ProfileManager(modelContext: modelContext!)
        }
        
        #if DEBUG
        // `UITEST_FRESH=1` means "start from nothing". The test that covers
        // profile creation needs onboarding, and the flag was passed but never
        // read — so the test passed or failed depending on whether an earlier
        // run had left a profile in the simulator's container.
        if ProcessInfo.processInfo.environment["UITEST_FRESH"] == "1",
           !Self.didResetForUITest,
           let modelContext {
            Self.didResetForUITest = true
            _ = DataResetService.resetAllData(modelContext: modelContext,
                                              profileManager: profileManager)
        }
        #endif

        // Always reload profiles and active profile (in case profile was just created/switched)
        profileManager?.loadProfiles()
        profileManager?.loadActiveProfile()

        // One-shot data fixes (profile-scoping + at-rest sealing). Runs after
        // profiles are loaded, since it needs to know which one is active, and
        // no-ops once the store is stamped.
        if let modelContext { StoreMigration.runIfNeeded(modelContext: modelContext) }

        // Demo mode: skip biometrics + server, present the seeded UI as if
        // already authenticated. Used to showcase the POC visuals.
        if PersistenceController.isDemo {
            hasActiveProfile = true
            if userService == nil { userService = UserService(api: session.api) }
            isAuthenticated = true
            connectionStatus = .authenticated
            return
        }

        // Check if we have an active profile
        if let profile = profileManager?.currentProfile {
            // Verify biometrics only ONCE per profile. initialize() is called
            // from several onAppear/task sites and re-runs on reconnect churn;
            // without this guard the Face ID prompt reappears constantly,
            // especially when offline (the connection keeps retrying).
            if unlockedProfileId != profile.id {
                // No gate here, and no prompt. Launch used to spend a Face ID
                // on a check that proved nothing, and the Keychain probes that
                // replaced it locked working profiles out instead — twice, for
                // opposite reasons. The handshake needs the key anyway and now
                // reports failure properly, so it is the only authority on key
                // access. This call is diagnostics only.
                profileManager?.hasStoredKey()
                unlockedProfileId = profile.id
            }
            hasActiveProfile = true
        } else {
            hasActiveProfile = false
            return // Show profile selection
        }
        
        // Initialize or reuse services
        if userService == nil {
            userService = UserService(api: session.api)
        }

        // Point the session at the current profile's store + identity. Recreated
        // on every initialize() so a profile switch cannot leave the router
        // writing into the previous profile's rows.
        session.configure(modelContext: modelContext!, profileManager: profileManager)

        // Set up callbacks
        // A dismissed unlock is a decision, not a network fault: stop retrying
        // and go back to profile selection rather than burning the auth grace
        // and re-prompting on a timer.
        session.onUnlockFailed = { [weak self] in
            guard let self else { return }
            print("[AppState] 🔒 Unlock dismissed — returning to profile selection")
            self.reconnectTask?.cancel()
            self.reconnectTask = nil
            self.isReconnecting = false
            self.unlockedProfileId = nil
            // Straight to profile selection, not the failure screen: a dismissed
            // unlock is a choice, and "Authentication Failed" overstates it.
            self.hasActiveProfile = false
            self.lastError = .validation("Unlock cancelled. Pick a profile to try again.")
            Task { await self.disconnectSession() }
        }

        session.onConnected = { [weak self] in
            self?.isAuthenticated = true
            self?.connectionStatus = .authenticated
            self?.connectionError = nil
            self?.blocked = false
            self?.notAdmitted = false
            // The door we came back through decides what this session can do.
            Task { [weak self] in
                guard let self else { return }
                let scope = await self.session.currentScope()
                await MainActor.run { self.scope = scope }
            }
            // The handshake is done. The hold expires on its own grace so the
            // friend `aes` burst that follows doesn't re-prompt; ProfileManager
            // owns that timer now (it is the only thing that knows when a burst
            // reopened the window, and a second timer out here would have closed
            // one early).
            // Ask for the message-read unlock HERE, where it cannot collide.
            //
            // The sign-in prompt has just been answered, so the biometric
            // hardware is free — no waiting, no interruption, no retry loop. The
            // screens that show message bodies still ask on appear, but SwiftUI
            // cancels a `.task` when its view rebuilds, and the conversation list
            // rebuilds exactly when conversations arrive; on a cold launch those
            // were the only requests and every one of them was torn down.
            //
            // Not the scene-phase handler either: `onChange` does not fire for
            // the INITIAL `.active`, so it covers returning to the app and never
            // opening it.
            Task { await MessageKeyGate.shared.unlock() }
            // A successful (re)auth ends any in-flight reconnect cycle.
            self?.reconnectAttempt = 0
            self?.reconnectTask?.cancel()
            self?.reconnectTask = nil
            // Register for push so the server can wake us when backgrounded.
            PushManager.shared.requestAndRegister()
            PushManager.shared.setSender { [weak self] token in
                try? await self?.userService?.registerPushToken(token)
            }
            // If a username was cached at profile creation, claim it now.
            Task { await self?.claimDesiredUsername() }
            // And ask the deployment whether it has anything to say. On connect
            // rather than on a timer: the thing it announces is a change being
            // made, and a client that just reconnected is the one most likely to
            // have been affected by it.
            Task { await self?.refreshMaintenanceNotice() }
        }
        
        session.onDisconnect = { [weak self] in
            self?.handleDisconnect()
        }

        session.onNotAdmitted = { [weak self] in
            guard let self else { return }
            // Not a paywall: this server will not serve this key at all (an
            // allowlist deployment). There is nothing to retry and nothing to
            // buy, so stop the reconnect loop and say so plainly.
            self.notAdmitted = true
            self.blocked = true
            self.isReconnecting = false
            self.reconnectTask?.cancel()
            self.reconnectTask = nil
            self.connectionStatus = .notAdmitted
        }
        
        // If the active profile changed since the last connection, tear the
        // stale socket + auth/subscription state down first. Otherwise
        // connectToServer() early-returns on the previous profile's
        // `.authenticated` status and the new profile shows the old one's
        // subscription state (and never re-auths).
        if let profileId = profileManager?.currentProfile?.id,
           let connected = connectedProfileId, connected != profileId {
            print("[AppState] 🔄 Active profile changed — resetting connection")
            await resetConnectionState()
        }

        // Connect (REST handshake, then MQTT).
        await connectToServer()
    }
    
    /// - Parameter force: bypass the "already connected" early-out. The manual
    ///   retry buttons and the scene-resume path pass this — otherwise a
    ///   stale-but-`.connected` socket makes retrying do nothing at all.
    ///
    ///   It says nothing about HOW to authenticate. It used to, and the cost was
    ///   a biometric prompt every time the app came back to the foreground; see
    ///   `performConnectAndAuth`.
    func connectToServer(force: Bool = false) async {
        // Don't connect if already connecting or connected
        if isConnecting && !force {
            return
        }

        if !force {
            switch connectionStatus {
            case .connected, .authenticated:
                return // Already connected
            default:
                break // Proceed with connection
            }
        }

        // No network path at all — say so instead of failing with a transport
        // error the user cannot act on.
        guard reachability.isOnline else {
            isConnecting = false
            connectionError = nil
            connectionStatus = .offline
            return
        }

        isConnecting = true
        connectionStatus = .connecting
        connectionError = nil

        do {
            try await performConnectAndAuth()
            isConnecting = false
        } catch {
            isConnecting = false
            if !reachability.isOnline {
                connectionError = nil
                connectionStatus = .offline
            } else {
                let errorMessage = Self.friendlyConnectError(error)
                connectionError = errorMessage
                connectionStatus = .error(errorMessage)
            }
            print("[AppState] ❌ Failed to connect: \(error)")
        }
    }

    /// Bring the link up. Shared by the initial connect and the reconnect loop;
    /// throws so the caller can report it.
    ///
    /// ALWAYS the cheap path. `session.reconnect()` rotates the MQTT token off
    /// the longer-lived REST bearer, and falls back to a full handshake by itself
    /// when that bearer is gone or the broker refuses the token — so it is a
    /// superset of `connect()`, never a weaker version of it.
    ///
    /// This used to branch on `force`, and that is how returning to the app cost
    /// a Face ID every single time. `force` means "do not skip this because you
    /// believe you are already connected" — the scene-resume path and every retry
    /// button pass it, for a stale-but-`.connected` socket — and it was ALSO read
    /// here as "re-authenticate from the private key". Two unrelated jobs on one
    /// flag, and the second one prompts.
    ///
    /// No needed handshake is lost: every caller that genuinely requires one — a
    /// profile switch — calls `resetConnectionState()` first,
    /// which clears the bearer via `session.logout()`, and `reconnect()` then
    /// reaches `connect()` on its own. The decision belongs to the session state,
    /// not to a caller's opinion about why it is calling.
    private func performConnectAndAuth() async throws {
        guard let currentProfile = profileManager?.currentProfile,
              currentProfile.publicKey != nil else {
            throw NSError(domain: "AppState", code: 1, userInfo: [NSLocalizedDescriptionKey: "No active profile"])
        }
        connectionStatus = .connected      // the UI labels this "Authenticating…"
        try await session.reconnect()
        // Remember which profile this connection authenticated as, so a later
        // profile switch knows it must tear it down and re-auth.
        connectedProfileId = currentProfile.id
    }

    /// Claim the handle chosen at profile creation, if there is one still
    /// pending. Under `/ws` this was fire-and-forget and a refusal came back as
    /// a pushed ERROR frame; over REST the call simply throws, which made it far
    /// too easy to swallow with `try?` — and swallowing it is exactly the bug
    /// that had a taken name re-requested, and re-alerted, at every launch.
    ///
    /// So: a refusal drops the doomed request and becomes a STATE the UI can
    /// offer a way out of (the banner above the tabs), not a modal.
    /// Ask the server whether it is mid-change, and show what it says.
    ///
    /// Failure is silence, not an error: a deployment that does not answer
    /// `/info` is one with nothing to announce, and a banner apologising for a
    /// missing banner would be worse than no banner. It also clears, so a notice
    /// disappears when the window closes without needing the app restarted.
    func refreshMaintenanceNotice() async {
        maintenanceNotice = await session.api.maintenanceNotice()
    }

    func claimDesiredUsername() async {
        guard let profile = profileManager?.currentProfile,
              let desired = profile.desiredUsername, !desired.isEmpty else { return }
        do {
            try await userService?.setUsername(desired)
            profile.desiredUsername = nil
            usernameRejected = nil
            try? modelContext?.save()
        } catch {
            guard Self.isUsernameTaken(error) else { return }  // transient — retry next connect
            usernameRejected = desired
            profile.desiredUsername = nil                      // stop re-firing it
            try? modelContext?.save()
        }
    }

    /// app-api answers a refused handle with `{"error":"USERNAME_TAKEN"}` (409).
    /// Matched on the code, not on prose, so a reworded message cannot turn this
    /// back into an unexplained failure.
    static func isUsernameTaken(_ error: Error) -> Bool {
        if case APIClient.APIError.badResponse(_, let body) = error {
            return body.contains("USERNAME_TAKEN")
        }
        return false
    }

    /// Tear down the live socket and clear connection/subscription state so the
    /// next connect re-auths cleanly as the (now different) active profile.
    private func resetConnectionState() async {
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectAttempt = 0
        isReconnecting = false
        await session.logout()
        isAuthenticated = false
        scope = .free
        notAdmitted = false
        blocked = false
        connectionError = nil
        connectionStatus = .disconnected
        connectedProfileId = nil
    }

    /// Called by `ChatSession` when the link drops unexpectedly.
    func handleDisconnect() {
        // Don't reconnect when the server has refused this key — it closed the
        // socket deliberately and would only refuse again.
        if blocked {
            isAuthenticated = false
            return
        }
        // Ignore if a reconnect cycle is already running.
        guard reconnectTask == nil else { return }
        isAuthenticated = false
        isReconnecting = true
        connectionStatus = reachability.isOnline ? .connecting : .offline
        scheduleReconnect()
    }

    /// Reconnect with jittered exponential backoff until auth succeeds.
    /// `setOnAuthSuccess` cancels this task on success.
    ///
    /// Two properties matter here. **Jitter** stops every client that dropped
    /// off a restarting server from retrying in lockstep. **Parking while
    /// offline** is the airplane-mode fix: the loop used to retry every 30 s
    /// forever with no network, each attempt building a fresh `URLSession` +
    /// `TLSPinningDelegate` and waking the radio for nothing.
    private func scheduleReconnect() {
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                // Park (not spin) until the device has a network path again.
                if !self.reachability.isOnline {
                    self.connectionStatus = .offline
                    self.reconnectAttempt = 0
                    await self.reachability.waitUntilOnline()
                    if Task.isCancelled { break }
                    self.connectionStatus = .connecting
                }

                let ceiling = min(pow(2.0, Double(self.reconnectAttempt)), Self.maxReconnectDelay)
                // Full jitter: uniform in [0, ceiling].
                let delay = Double.random(in: 0...ceiling)
                print("[AppState] 🔄 Reconnect attempt \(self.reconnectAttempt + 1) in \(String(format: "%.1f", delay))s")
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                if Task.isCancelled { break }
                self.reconnectAttempt += 1

                do {
                    // Cheap path, like every other caller: the backoff loop runs
                    // after a dropped link, which is exactly when the REST bearer
                    // is still good and only the MQTT token needs rotating. It
                    // passed `force: true` here, so every single retry attempt
                    // re-ran the handshake and prompted for Face ID.
                    try await self.performConnectAndAuth()
                } catch {
                    print("[AppState] ⚠️ Reconnect attempt failed: \(error)")
                    continue
                }

                // Wait for the auth handshake to land. On success onAuthSuccess
                // cancels this task; this bounded poll is the failure path.
                if await self.awaitAuthentication(timeout: Self.authGrace) {
                    self.isReconnecting = false
                    break
                }
                if Task.isCancelled { break }
            }
        }
    }

    /// Polls for the auth handshake to complete, up to `timeout`. Replaces a
    /// hard-coded 3 s sleep that made every reconnect take at least that long.
    private func awaitAuthentication(timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if Task.isCancelled { return false }
            if case .authenticated = connectionStatus { return true }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        if case .authenticated = connectionStatus { return true }
        return false
    }

    /// Server `ERROR` payloads are either a known code or free-form text.
    /// Codes get a written explanation; anything else passes through.
    private static func serverErrorMessage(_ payload: String) -> String {
        switch payload {
        case "USER_NOT_FOUND":
            return "No account with that username."
        case "USERNAME_TAKEN":
            return "That username is already taken. Try another."
        case "NOT_FRIENDS":
            return "You're not connected with that person."
        case "INVALID_MESSAGE", "INVALID_PAYLOAD":
            return "The server rejected that request."
        case "RATE_LIMITED":
            return "Too many requests. Wait a moment and try again."
        default:
            return payload
        }
    }

    private static func friendlyConnectError(_ error: Error) -> String {
        // Match on `URLError.Code` rather than substrings of
        // `localizedDescription`, which is locale-dependent — and which had no
        // branch at all for the actual airplane-mode error (-1009).
        if let urlError = error as? URLError {
            switch urlError.code {
            case .notConnectedToInternet:
                return "No internet connection.\n\nCheck Wi-Fi or cellular and try again."
            case .networkConnectionLost:
                return "The connection was lost.\n\nRetrying automatically."
            case .timedOut:
                return "The server took too long to respond.\n\nIt may be overloaded or unreachable."
            case .cannotConnectToHost, .cannotFindHost:
                return "Cannot reach the server.\n\nPlease check the server address and try again."
            case .secureConnectionFailed, .serverCertificateUntrusted,
                 .serverCertificateHasBadDate, .serverCertificateNotYetValid,
                 .serverCertificateHasUnknownRoot:
                return "The server's security certificate was rejected.\n\nThe connection was refused to protect your messages."
            default:
                break
            }
        }

        let description = error.localizedDescription
        if description.contains("Socket is not connected") {
            return "Cannot connect to the server.\n\nPlease ensure the server is running and accessible."
        }
        return "Connection failed. The server may be offline or unreachable.\n\nError: \(description)"
    }
    
    /// Called when the app returns to the foreground. Coming back from
    /// background (or from airplane mode) used to leave the user waiting out
    /// the backoff timer, which could be a full 30 s of looking at a dead app.
    func reconnectIfNeeded() async {
        guard hasActiveProfile, !blocked else { return }
        // `isAuthenticated` is our *belief* about the connection, and it can be
        // stale: a socket that died while the app was suspended leaves the flag
        // true with nothing behind it. Ask the socket, not the flag — otherwise
        // this returns early forever and the app never reconnects.
        // Live and authenticated: nothing to do. `enterForeground()` runs just
        // before this on iOS and has already re-announced presence.
        if isAuthenticated, session.isConnected { return }
        isAuthenticated = false
        // A connection attempt is already running — most often at cold launch,
        // where `initialize()` connects and the scene going `.active` fires this
        // a moment later. Forcing a second one there cancelled the first
        // mid-handshake and cost an extra auth (and an extra Face ID).
        guard !isConnecting else { return }
        guard reachability.isOnline else {
            connectionStatus = .offline
            return
        }
        // A reconnect loop is already running — restart its backoff so it
        // retries now rather than at the end of the current delay.
        if reconnectTask != nil {
            reconnectAttempt = 0
            scheduleReconnect()
            return
        }
        await connectToServer(force: true)
    }

    func authenticate() async {
        // If we already have services set up, just connect
        // Otherwise, initialize everything
        if userService == nil {
            await initialize()
        } else {
            // Services already initialized, just connect with current profile
            await connectToServer()
        }
    }
    
    func getSession() -> ChatSession {
        return session
    }

    func disconnectSession() async {
        await session.disconnect()
    }

    // MARK: - Account

    /// Permanently delete the account (App Store Guideline 5.1.1(v)): ask the
    /// server to purge all server-side data while we're still authenticated,
    /// then tear down the connection and wipe everything on this device.
    /// Returns to profile selection. Best-effort on the server call — local
    /// data is always wiped so the user is never stuck half-deleted.
    func deleteAccount() async {
        if isAuthenticated {
            // A REST call: it has either landed or failed by the time it returns,
            // so there is nothing to flush before tearing the connection down.
            try? await userService?.deleteAccount()
        }
        await resetConnectionState()
        if let modelContext {
            _ = DataResetService.resetAllData(modelContext: modelContext, profileManager: profileManager)
        }
        profileManager?.loadProfiles()
        hasActiveProfile = false
    }
}
