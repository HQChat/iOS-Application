//
//  DissQus_iOSApp.swift
//  DissQus iOS
//
//  iOS entry point. Mirrors DissQusApp (macOS): launches the shared
//  ContentView with the shared AppState and SwiftData container.
//

import SwiftUI
import SwiftData

@main
struct DissQus_iOSApp: App {
    let persistenceController = PersistenceController.shared
    @StateObject private var appState = AppState()
    @UIApplicationDelegateAdaptor(PushAppDelegate.self) private var pushDelegate
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Init Sentry crash reporting + memory-pressure early warning before any
        // app code runs, so a crash during startup is still captured.
        Observability.start()
    }

    var body: some Scene {
        WindowGroup {
            ZStack {
                ContentView()
                    .environmentObject(appState)
                    .modelContainer(persistenceController.container)
                    .task {
                        await appState.initialize()
                    }
            }
            .onChange(of: scenePhase) { _, phase in
                switch phase {
                case .background:
                    // Tell the server first, while we still have a moment to
                    // send: from here on, messages must be queued and pushed
                    // rather than relayed into a socket iOS is about to freeze.
                    Task { await appState.enterBackground() }
                    // Fast unlock holds the identity key in memory; don't retain
                    // it while the app isn't in use. macOS already did this —
                    // iOS did not, contradicting the setting's own description.
                    appState.clearCachedKey()
                case .active:
                    Task {
                        // If the socket survived the background, this asks for
                        // whatever queued while we were away — no reconnect, so
                        // no second handshake and no second Face ID.
                        await appState.enterForeground()
                        // And if it didn't survive, don't make the user wait out
                        // the reconnect backoff.
                        await appState.reconnectIfNeeded()
                    }
                    // Going to background dropped the read context above
                    // (`clearCachedKey`), so coming back has to ask again — and
                    // this is the only place on iOS that can. The screens ask
                    // from a `.task`, which does not re-run for a view that
                    // stayed on screen, and `onAuthSuccess` only fires when the
                    // socket did NOT survive. Without this, returning to the app
                    // left every row reading "🔒 locked" with nothing left to
                    // ask. macOS has had this since #84; the iOS shell is a
                    // separate file and simply never got it.
                    Task { await MessageKeyGate.shared.unlock() }
                default: break
                }
            }
        }
    }
}
