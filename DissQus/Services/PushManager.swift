//
//  PushManager.swift
//  DissQus
//
//  Registers for Apple Push Notifications and forwards the device token to the
//  server so it can wake the app for messages/calls while backgrounded.
//
//  Activation checklist (one-time, in the Apple Developer setup):
//   - Add the "Push Notifications" capability/entitlement to each target.
//   - Add an APNs Auth Key (.p8) to the server (see deploy/.env.example).
//

import Foundation
import UserNotifications
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

@MainActor
final class PushManager: ObservableObject {
    static let shared = PushManager()

    @Published private(set) var deviceToken: String?
    /// Delivers a token to the server. Set once we're authenticated.
    private var sender: ((String) async -> Void)?

    private var platform: String {
        #if os(iOS)
        return "ios"
        #else
        return "macos"
        #endif
    }

    /// Ask permission and register for remote notifications. Safe to call repeatedly.
    func requestAndRegister() {
        let center = UNUserNotificationCenter.current()
        // One notification owner: NotificationService decides how anything is
        // presented, including pushes that land while the app is open.
        center.delegate = NotificationService.shared
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error { print("[Push] authorization error: \(error)") }
            guard granted else { print("[Push] notifications not granted"); return }
            DispatchQueue.main.async {
                #if os(iOS)
                UIApplication.shared.registerForRemoteNotifications()
                #elseif os(macOS)
                NSApplication.shared.registerForRemoteNotifications()
                #endif
            }
        }
    }

    /// Called by the app delegate when APNs returns a token.
    func didRegister(tokenData: Data) {
        let token = tokenData.map { String(format: "%02x", $0) }.joined()
        deviceToken = token
        print("[Push] device token: \(token.prefix(12))…")
        Task { await sender?("\(platform):\(token)") }
    }

    /// Wire up token delivery (called after auth). Flushes immediately if a
    /// token is already in hand.
    func setSender(_ sender: @escaping (String) async -> Void) {
        self.sender = sender
        if let token = deviceToken {
            Task { await sender("\(platform):\(token)") }
        }
    }
}

// MARK: - App delegate (SwiftUI needs this for the token callbacks)

#if os(iOS)
final class PushAppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in PushManager.shared.didRegister(tokenData: deviceToken) }
    }
    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        print("[Push] failed to register: \(error)")
    }
}
#elseif os(macOS)
final class PushAppDelegate: NSObject, NSApplicationDelegate {
    func application(_ application: NSApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in PushManager.shared.didRegister(tokenData: deviceToken) }
    }
    func application(_ application: NSApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        print("[Push] failed to register: \(error)")
    }
}
#endif
