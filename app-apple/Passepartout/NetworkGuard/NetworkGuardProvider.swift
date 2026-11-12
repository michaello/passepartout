// SPDX-License-Identifier: GPL-3.0

import Foundation
import Network
import NetworkExtension
import os

final class NetworkGuardProvider: NEFilterPacketProvider {
    private let logger = Logger(subsystem: "com.algoritmico.mac.Passepartout.NetworkGuard", category: "prototype")
    private let observations = PacketObservations()

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Capture an immutable, OS-persisted policy before installing the handler.
        // No app connection or VPN-status notification can turn this into allow-all.
        let policy = NetworkGuardPolicy(configuration: filterConfiguration.vendorConfiguration)
        let observations = observations
        let logger = logger
        packetHandler = { _, interface, direction, bytes, length in
            guard direction == .outbound || direction == .inbound else { return .drop }
            let frame = UnsafeRawBufferPointer(start: bytes, count: length)
            let allowed = policy.allows(frame, outbound: direction == .outbound)
            let name = String(cString: nw_interface_get_name(interface))
            if observations.record(interface: name, outbound: direction == .outbound, allowed: allowed) {
                // Metadata only; never log packet content, addresses, or credentials.
                logger.notice("First packet: interface=\(name, privacy: .public) outbound=\(direction == .outbound) allowed=\(allowed) length=\(length)")
            }
            return allowed ? .allow : .drop
        }
        logger.warning("Prototype started with \(policy.endpoints.count) endpoint exceptions. Authorized inner-tunnel traffic is not implemented. Persistence is unverified.")
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Leave the drop-capable handler installed for the remainder of our lifetime.
        // The OS behavior after process termination is an explicit release gate.
        logger.warning("Prototype stopping: reason=\(reason.rawValue) observations=\(self.observations.summary(), privacy: .public)")
        completionHandler()
    }
}

private final class PacketObservations {
    private let lock = NSLock()
    private var counts: [String: UInt64] = [:]

    /// One diagnostic per interface/direction/verdict, with bounded storage.
    func record(interface: String, outbound: Bool, allowed: Bool) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let key = "\(interface):\(outbound ? "out" : "in"):\(allowed ? "allow" : "drop")"
        if let count = counts[key] {
            counts[key] = count == .max ? .max : count + 1
            return false
        }
        guard counts.count < 256 else { return false }
        counts[key] = 1
        return true
    }

    func summary() -> String {
        lock.lock()
        defer { lock.unlock() }
        return counts.keys.sorted().map { "\($0)=\(counts[$0]!)" }.joined(separator: ",")
    }
}
