//
//  Reachability.swift
//  DissQus
//
//  Device-level network reachability, shared by macOS and iOS.
//

import Foundation
import Network

/// Tracks whether the device has a usable network path.
///
/// The app previously had no notion of this at all, which made three separate
/// failures indistinguishable: `URLSessionWebSocketTask.resume()` does not throw
/// without a network, so an offline device looked exactly like a server outage,
/// and the reconnect loop kept spinning up a fresh `URLSession` every 30 s
/// forever — burning radio wake-ups with no chance of succeeding.
@MainActor
final class Reachability: ObservableObject {
    @Published private(set) var isOnline: Bool = true
    @Published private(set) var isExpensive: Bool = false
    @Published private(set) var isConstrained: Bool = false

    /// Fired on an offline → online transition. The app uses it to wake the
    /// reconnect loop immediately instead of waiting out its backoff.
    var onBecameOnline: (() -> Void)?

    private let monitor = NWPathMonitor()
    private static let queue = DispatchQueue(label: "me.rougeron.dissqus.reachability")
    /// Callers parked in `waitUntilOnline()`, resumed together on the next
    /// offline → online transition.
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init() {
        monitor.pathUpdateHandler = { [weak self] path in
            let online = path.status == .satisfied
            let expensive = path.isExpensive
            let constrained = path.isConstrained
            Task { @MainActor in
                self?.apply(online: online, expensive: expensive, constrained: constrained)
            }
        }
        monitor.start(queue: Self.queue)
    }

    /// Suspends until the device is back online. The reconnect loop awaits this
    /// so it parks instead of retrying into a dead radio.
    func waitUntilOnline() async {
        if isOnline { return }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            waiters.append(cont)
        }
    }

    private func apply(online: Bool, expensive: Bool, constrained: Bool) {
        let wasOnline = isOnline
        isOnline = online
        isExpensive = expensive
        isConstrained = constrained

        guard online, !wasOnline else { return }
        let parked = waiters
        waiters.removeAll()
        parked.forEach { $0.resume() }
        onBecameOnline?()
    }
}
