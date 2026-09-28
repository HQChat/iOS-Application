import Foundation

// The rule that decides whether a network path update should drop a live MQTT
// link (Services/Reachability.swift, compiled in by run.sh). NWPathMonitor
// reports far more than interface moves — cost, constraint, DNS and gateway
// changes all arrive as updates — so reconnecting on every one would tear down
// healthy links; never reconnecting leaves a socket stranded on an address the
// device no longer has.

var failures = 0
func check(_ label: String, _ condition: Bool) {
    if condition { print("  ✓ \(label)") }
    else { print("  ✗ \(label)"); failures += 1 }
}

typealias S = NetworkPathChange.Snapshot
let wifi = S(online: true, primary: .wifi)
let cell = S(online: true, primary: .cellular)
let wired = S(online: true, primary: .wired)
let offline = S(online: false, primary: nil)

print("network path change")
check("the monitor's first report is not a change",
      NetworkPathChange.classify(from: nil, to: wifi) == .none)
check("the same interface again is not a change",
      NetworkPathChange.classify(from: wifi, to: wifi) == .none)
check("Wi-Fi to cellular is an interface change",
      NetworkPathChange.classify(from: wifi, to: cell) == .interfaceChanged)
check("cellular to Wi-Fi is an interface change",
      NetworkPathChange.classify(from: cell, to: wifi) == .interfaceChanged)
check("Wi-Fi to wired is an interface change",
      NetworkPathChange.classify(from: wifi, to: wired) == .interfaceChanged)
check("losing the path is going offline, not an interface change",
      NetworkPathChange.classify(from: wifi, to: offline) == .wentOffline)
check("regaining it is coming online",
      NetworkPathChange.classify(from: offline, to: cell) == .becameOnline)
check("offline to offline is nothing",
      NetworkPathChange.classify(from: offline, to: offline) == .none)

print("")
if failures > 0 {
    print("✗ \(failures) reachability check(s) failed")
    exit(1)
}
print("✓ Reachability OK")
