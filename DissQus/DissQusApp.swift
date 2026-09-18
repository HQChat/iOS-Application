//
//  DissQusApp.swift
//  DissQus
//
//  Created by Martin Rougeron on 20/12/2025.
//

import SwiftUI
import SwiftData

@main
struct DissQusApp: App {
    let persistenceController = PersistenceController.shared
    @StateObject private var appState = AppState()
    @NSApplicationDelegateAdaptor(PushAppDelegate.self) private var pushDelegate
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
                    // Unsecure mode: don't retain the key while backgrounded.
                    appState.clearCachedKey()
                case .active:
                    // Don't make the user wait out the reconnect backoff after
                    // coming back from background or a network drop.
                    Task { await appState.reconnectIfNeeded() }
                    // And ask for the message unlock from somewhere STABLE. The
                    // screens that show bodies ask too, but SwiftUI cancels a
                    // `.task` whenever its view rebuilds — and the view that
                    // lists conversations rebuilds exactly when conversations
                    // arrive. This scene handler outlives all of that.
                    Task { await MessageKeyGate.shared.unlock() }
                default: break
                }
            }
        }
    }
}
