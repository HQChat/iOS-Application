//
//  ContentView.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import SwiftUI
import Combine
import SwiftData
import CryptoKit
#if os(iOS)
import CoreImage.CIFilterBuiltins
import UIKit
#endif

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.modelContext) private var modelContext
    /// `HQFont` scales through `UIFontMetrics`, which reads UIKit's content-size
    /// category rather than the SwiftUI environment — so SwiftUI has no reason
    /// to re-evaluate anything when the reader changes their text size. Keying
    /// the root on it gives it one.
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    
    var body: some View {
        Group {
            if !appState.hasActiveProfile {
                // Show profile selection
                if let profileManager = appState.profileManager {
                    ProfileSelectionView(profileManager: profileManager)
                        .onChange(of: profileManager.currentProfile) { _, newProfile in
                            if newProfile != nil {
                                appState.hasActiveProfile = true
                                // Initialize services and connect with new profile
                                Task {
                                    await appState.disconnectSession()
                                    // Reinitialize to set up services with new profile
                                    await appState.initialize()
                                }
                            }
                        }
                } else {
                    LoadingView(message: "Initializing profiles...")
                        .onAppear {
                            Task {
                                await appState.initialize()
                            }
                        }
                }
            } else if appState.hasActiveProfile {
                // We have a profile, show main app (even if not authenticated yet)
                if let userService = appState.userService {
                    MainAppView(
                        session: appState.getSession(),
                        userService: userService,
                        profileManager: appState.profileManager
                    )
                } else {
                    LoadingView(message: "Initializing...")
                        .onAppear {
                            Task {
                                await appState.authenticate()
                            }
                        }
                }
            } else {
                // Unreachable in practice: the two branches above partition on
                // `hasActiveProfile`. Kept as a safe fallback rather than a
                // second, unthemed status screen.
                LoadingView(message: "Starting…")
            }
        }
        // One presentation point for errors that arrive with no owning screen:
        // server ERROR frames and call failures, both of which were previously
        // logged and dropped.
        .hqError($appState.lastError)
        .id(dynamicTypeSize)
        .onAppear {
            Task {
                await appState.initialize()
            }
        }
        // hqchat is a dark-first experience; force the dark scheme so system
        // surfaces (lists, sheets, nav bars) harmonize with the themed screens.
        .preferredColorScheme(.dark)
        .tint(HQColor.green)
    }
}

/// Compact connection-status indicator shown in the top-right of the friends
/// list (replacing the old full-width banner). A spinner while connecting /
/// authenticating, a green encrypted glyph when healthy, and a tappable
/// red/grey glyph (retries the connection) when something is wrong.
struct ConnectionStatusButton: View {
    @ObservedObject var appState: AppState

    private var spec: (symbol: String, color: Color, spinning: Bool, help: String)? {
        switch appState.connectionStatus {
        case .authenticated:
            return ("lock.fill", HQColor.green, false, "Connected · end-to-end encrypted")
        case .notAdmitted:
            return ("hand.raised.fill", HQColor.warning, false,
                    "This server does not accept this key")
        case .connecting:
            return ("arrow.triangle.2.circlepath", HQColor.warning, true,
                    appState.isReconnecting ? "Reconnecting…" : "Connecting…")
        case .connected:
            return ("lock.rotation", HQColor.purpleLight, true, "Authenticating…")
        case .disconnected:
            return ("wifi.slash", HQColor.textMuted, false, "Disconnected — tap to reconnect")
        case .offline:
            return ("airplane", HQColor.textSecond, false, "No network — waiting for a connection")
        case .error:
            return ("exclamationmark.triangle.fill", HQColor.danger, false, "Connection lost — tap to retry")
        }
    }

    private var isActionable: Bool {
        switch appState.connectionStatus {
        case .disconnected, .error: return true
        // Offline is not actionable — retrying without a network path cannot
        // succeed, and the app resumes on its own when the path returns.
        case .offline: return false
        default: return false
        }
    }

    var body: some View {
        if let spec {
            Button {
                if isActionable { Task { await appState.connectToServer(force: true) } }
            } label: {
                ZStack {
                    if spec.spinning {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: spec.symbol)
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(spec.color)
                    }
                }
                .frame(width: 30, height: 30)
                .background(spec.color.opacity(0.12))
                .clipShape(Circle())
                .overlay(Circle().stroke(spec.color.opacity(0.4), lineWidth: 1))
            }
            .buttonStyle(.plain)
            .disabled(!isActionable)
            .help(spec.help)
            .animation(.easeInOut(duration: 0.2), value: appState.isReconnecting)
        }
    }
}

/// The header every parent screen wears. Screens pass only their name — the
/// status chip, the server-info button and its sheet live here, so Chats,
/// Contacts and Settings cannot end up with three different top bars (which is
/// exactly what happened when each screen assembled its own).
struct HQScreenHeader: View {
    let path: String
    @ObservedObject var appState: AppState
    var profileManager: ProfileManager?

    @State private var showingServerInfo = false

    var body: some View {
        HQPromptHeader(path: path) {
            HStack(spacing: 10) {
                ConnectionStatusChip(appState: appState)
                ServerInfoButton(appState: appState) { showingServerInfo = true }
            }
        }
        .sheet(isPresented: $showingServerInfo) {
            ServerInfoView(
                appState: appState,
                serverURL: ServerConfig.apiBaseURL
            )
        }
    }
}

/// The connection state as a terminal readout: a lit dot and a short uppercase
/// code, for the right-hand side of `HQPromptHeader`. Tapping retries when a
/// retry can actually help — same rule as `ConnectionStatusButton`.
struct ConnectionStatusChip: View {
    @ObservedObject var appState: AppState

    var body: some View {
        let status = appState.connectionStatus
        Button {
            if status.canReconnect { Task { await appState.connectToServer(force: true) } }
        } label: {
            HStack(spacing: 5) {
                Circle()
                    .fill(status.indicatorColor)
                    .frame(width: 6, height: 6)
                    .shadow(color: status.indicatorColor.opacity(0.9), radius: 4)
                Text(status.terminalCode)
                    .font(HQFont.mono(10.5, weight: .bold))
                    .tracking(1)
                    .lineLimit(1)
                    .fixedSize()
                    .foregroundColor(status.indicatorColor)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .overlay(Rectangle().stroke(status.indicatorColor.opacity(0.35), lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!status.canReconnect)
        .help(status.label)
        .hqGlitch(on: status)
    }
}

extension AppState.ConnectionStatus {
    /// Short machine code for the prompt header.
    var terminalCode: String {
        switch self {
        case .authenticated:   return "SECURE"
        case .connecting:      return "LINK.."
        case .connected:       return "AUTH.."
        case .notAdmitted: return "REFUSED"
        case .disconnected:    return "DOWN"
        case .offline:         return "NO NET"
        case .error:           return "ERROR"
        }
    }

    /// Shared status colour for the toolbar dot and the info sheet.
    var indicatorColor: Color {
        switch self {
        case .authenticated:          return HQColor.green
        case .connecting, .connected: return HQColor.warning
        case .notAdmitted:            return HQColor.warning
        case .disconnected:           return HQColor.textMuted
        case .offline:                return HQColor.textSecond
        case .error:                  return HQColor.danger
        }
    }

    /// Human-readable connection state for the info sheet.
    var label: String {
        switch self {
        case .authenticated:   return "Connected · end-to-end encrypted"
        case .connecting:      return "Connecting…"
        case .connected:       return "Authenticating…"
        case .notAdmitted: return "This server does not accept this key"
        case .disconnected:    return "Disconnected"
        case .offline:         return "No network"
        case .error:           return "Connection error"
        }
    }

    /// Whether a manual reconnect makes sense from this state.
    var canReconnect: Bool {
        switch self {
        case .disconnected, .error: return true
        default:                    return false
        }
    }
}

/// Toolbar leading indicator: a single server glyph, green when connected and
/// grey otherwise. Tapping opens `ServerInfoView`. Server state lives on the
/// left; the right edge is reserved for actions (Add Friend, …).
struct ServerInfoButton: View {
    @ObservedObject var appState: AppState
    let action: () -> Void

    private var isConnected: Bool {
        if case .authenticated = appState.connectionStatus { return true }
        return false
    }

    var body: some View {
        Button(action: action) {
            Image(systemName: "server.rack")
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(isConnected ? HQColor.green : HQColor.textMuted)
        }
        .buttonStyle(.plain)
        .help("Server info")
        .animation(.easeInOut(duration: 0.2), value: isConnected)
    }
}

/// Read-only summary of the server this profile is attached to: host, address,
/// live connection status, and the transport/encryption guarantee. Offers a
/// manual reconnect when the socket is down.
struct ServerInfoView: View {
    @ObservedObject var appState: AppState
    let serverURL: URL
    @Environment(\.dismiss) private var dismiss

    private var host: String { serverURL.host ?? serverURL.absoluteString }
    /// wss/https → secure transport.
    private var isSecure: Bool { (serverURL.scheme ?? "").hasSuffix("s") }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    infoRow("Host", host)
                    infoRow("Address", serverURL.absoluteString)
                    HStack {
                        Text("Status").foregroundColor(HQColor.textSecond)
                        Spacer()
                        HStack(spacing: 6) {
                            Circle()
                                .fill(appState.connectionStatus.indicatorColor)
                                .frame(width: 8, height: 8)
                            Text(appState.connectionStatus.label)
                                .foregroundColor(HQColor.textPrimary)
                        }
                    }
                } header: {
                    Text("Server")
                } footer: {
                    Text(isSecure
                         ? "Transport is TLS-encrypted; messages are end-to-end encrypted with post-quantum HQC keys."
                         : "⚠︎ This server uses an unencrypted transport.")
                }

                if appState.connectionStatus.canReconnect {
                    Section {
                        Button {
                            Task { await appState.connectToServer(force: true) }
                            dismiss()
                        } label: {
                            Label("Reconnect", systemImage: "arrow.clockwise")
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Server Info")
            .inlineNavTitle()
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .sheetSizing()
    }

    @ViewBuilder
    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundColor(HQColor.textSecond)
            Spacer()
            Text(value)
                .font(HQFont.mono(13))
                .foregroundColor(HQColor.textPrimary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }
}

struct MainAppView: View {
    @EnvironmentObject var appState: AppState
    let session: ChatSession
    let userService: UserService
    let profileManager: ProfileManager?
    @State private var showingProfileSelection = false
    
    private var friendList: some View {
        FriendListView(session: session, userService: userService, profileManager: profileManager)
    }

    @ViewBuilder
    private var adaptiveContent: some View {
        #if os(macOS)
        // Desktop: fixed-width profile sidebar beside the friend list.
        HStack(spacing: 0) {
            VStack {
                if let currentProfile = profileManager?.currentProfile {
                    VStack(spacing: 8) {
                        Image(systemName: "person.circle.fill")
                            .font(.system(size: 32))
                            .foregroundColor(.blue)

                        Text("@\(currentProfile.username)")
                            .font(.caption)
                            .fontWeight(.medium)
                            .lineLimit(1)
                            .truncationMode(.tail)

                        Button {
                            showingProfileSelection = true
                        } label: {
                            Text("Switch")
                                .font(.caption2)
                        }
                        .buttonStyle(.bordered)
                    }
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color.controlBackground)
                }

                Spacer()
            }
            .frame(width: 120)
            .background(Color.controlBackground)

            Divider()

            friendList
        }
        #else
        // iPhone: a bottom tab bar (Chats / Contacts / Settings). This replaces
        // the old single list plus a "…" toolbar menu that hid Settings, the
        // profile switcher, and Refresh behind two taps each.
        RootTabView(
            session: session,
            userService: userService,
            profileManager: profileManager
        )
        #endif
    }

    var body: some View {
        VStack(spacing: 0) {
            // One banner for both platforms. iOS and macOS otherwise surface
            // connection state through entirely different toolbar glyphs, and
            // iOS had no visible reconnecting/offline indication at all.
            ConnectionBanner(appState: appState)
            // Session-wide status, above the platform fork for the same reason:
            // anything rendered below it belongs to one shell, and a banner
            // that belongs to one shell is a banner the other one loses.
            AppStatusBanners(appState: appState)
            adaptiveContent
        }
        #if os(iOS)
        // Full screen, not a sheet: this screen paints its own full-bleed
        // backdrop, and a system sheet clipped it into a rounded card with the
        // previous screen showing above it — neither one thing nor the other.
        .fullScreenCover(isPresented: $showingProfileSelection) {
            profileSelectionSheet { showingProfileSelection = false }
        }
        .fullScreenCover(isPresented: $appState.showingProfileSwitcher) {
            profileSelectionSheet { appState.showingProfileSwitcher = false }
        }
        #else
        .sheet(isPresented: $showingProfileSelection) {
            profileSelectionSheet { showingProfileSelection = false }
        }
        .sheet(isPresented: $appState.showingProfileSwitcher) {
            profileSelectionSheet { appState.showingProfileSwitcher = false }
        }
        #endif
    }

    @ViewBuilder
    private func profileSelectionSheet(onSwitched: @escaping () -> Void) -> some View {
        if let profileManager = profileManager {
            ProfileSelectionView(profileManager: profileManager, onClose: onSwitched)
                .onChange(of: profileManager.currentProfile) { _, newProfile in
                    if newProfile != nil { onSwitched() }
                }
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(AppState())
        .modelContainer(for: [Friend.self, Message.self])
}
