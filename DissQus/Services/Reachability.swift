//
//  Reachability.swift
//  DissQus
//
//  Device-level network reachability, shared by macOS and iOS.
//

import Foundation
import Network

/// What a path update means for a live connection. Pure, so the rule is tested
/// without a monitor: NWPathMonitor reports far more than interface moves —
/// `isExpensive`, `isConstrained`, DNS and gateway changes all arrive as
/// updates — and reconnecting on every one would drop a healthy link for
/// nothing.
enum NetworkPathChange: Equatable {
    /// The kind of interface the system prefers. Coarse on purpose: a move
    /// between two kinds is the case that strands a socket on an address the
    /// device no longer has.
    enum Interface: Equatable { case wifi, cellular, wired, other }

    struct Snapshot: Equatable {
        var online: Bool
        var primary: Interface?
    }

    case none
    case wentOffline
    case becameOnline
    /// Still online, but on a different kind of interface. Sockets opened on
    /// the old one are presumed dead.
    case interfaceChanged

    static func classify(from old: Snapshot?, to new: Snapshot) -> NetworkPathChange {
        guard let old else { return .none }   // the monitor's first report is not a change
        switch (old.online, new.online) {
        case (true, false): return .wentOffline
        case (false, true): return .becameOnline
        case (false, false): return .none
        case (true, true): return old.primary == new.primary ? .none : .interfaceChanged
        }
    }
}

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
    /// Fired when the device stays online but moves to another kind of
    /// interface (Wi-Fi to cellular and back). A connection opened on the old
    /// one is bound to an address the device may no longer have.
    var onInterfaceChanged: (() -> Void)?

    private let monitor = NWPathMonitor()
    private static let queue = DispatchQueue(label: "me.rougeron.dissqus.reachability")
    /// Callers parked in `waitUntilOnline()`, resumed together on the next
    /// offline → online transition.
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var lastSnapshot: NetworkPathChange.Snapshot?

    /// The current network KIND, readable off the main actor — what the
    /// transport selector remembers a blocked gateway port against.
    nonisolated static var currentNetworkKey: String {
        keyLock.lock(); defer { keyLock.unlock() }
        return _currentNetworkKey
    }
    nonisolated(unsafe) private static var _currentNetworkKey = "unknown"
    private static let keyLock = NSLock()

    init() {
        monitor.pathUpdateHandler = { [weak self] path in
            let online = path.status == .satisfied
            let expensive = path.isExpensive
            let constrained = path.isConstrained
            let primary = Self.interface(of: path)
            Task { @MainActor in
                self?.apply(online: online, expensive: expensive, constrained: constrained,
                            primary: primary)
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

    nonisolated private static func interface(of path: NWPath) -> NetworkPathChange.Interface? {
        guard path.status == .satisfied, let first = path.availableInterfaces.first else { return nil }
        switch first.type {
        case .wifi: return .wifi
        case .cellular: return .cellular
        case .wiredEthernet: return .wired
        default: return .other
        }
    }

    private func apply(online: Bool, expensive: Bool, constrained: Bool,
                       primary: NetworkPathChange.Interface?) {
        let wasOnline = isOnline
        isOnline = online
        isExpensive = expensive
        isConstrained = constrained

        let snapshot = NetworkPathChange.Snapshot(online: online, primary: primary)
        let change = NetworkPathChange.classify(from: lastSnapshot, to: snapshot)
        lastSnapshot = snapshot
        Self.keyLock.lock()
        Self._currentNetworkKey = online ? "\(primary.map { "\($0)" } ?? "other")" : "offline"
        Self.keyLock.unlock()
        if change == .interfaceChanged { onInterfaceChanged?() }

        guard online, !wasOnline else { return }
        let parked = waiters
        waiters.removeAll()
        parked.forEach { $0.resume() }
        onBecameOnline?()
    }
}
