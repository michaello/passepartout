// SPDX-License-Identifier: GPL-3.0

#if os(macOS)
import Foundation
import Network
import NetworkExtension

/// Configuration for the isolated enforcement prototype. This does not install,
/// save, enable, or claim to verify a filter. It is not a production arming driver.
@available(macOS 27.0, *)
public enum NetworkGuardPrototypeConfiguration {
    public enum ConfigurationError: Error {
        case invalidApplicationIdentifier
        case invalidEndpoint
        case invalidEndpointCount
        case invalidExpiry
    }

    public enum Transport: Int, Sendable {
        case tcp = 6
        case udp = 17
    }

    public struct Endpoint: Sendable {
        let address: String
        let transport: Transport
        let port: UInt16

        public init(address: String, transport: Transport, port: UInt16) throws {
            guard port != 0,
                  IPv4Address(address) != nil || IPv6Address(address) != nil else {
                throw ConfigurationError.invalidEndpoint
            }
            self.address = address
            self.transport = transport
            self.port = port
        }
    }

    /// A future installation driver can assign the result to
    /// NEFilterManager.providerConfiguration. A saved filter configuration alone
    /// does not establish active enforcement, boot persistence, or crash behavior.
    /// The prototype has no authorized inner-tunnel path and can block VPN traffic.
    public static func make(
        applicationBundleIdentifier: String,
        endpoints: [Endpoint],
        expiresAt: Date,
        now: Date = Date()
    ) throws -> NEFilterProviderConfiguration {
        guard (1...32).contains(endpoints.count) else { throw ConfigurationError.invalidEndpointCount }
        guard expiresAt.timeIntervalSince1970.isFinite, expiresAt > now else {
            throw ConfigurationError.invalidExpiry
        }
        let identifier = try providerBundleIdentifier(for: applicationBundleIdentifier)
        let configuration = NEFilterProviderConfiguration()
        configuration.filterPackets = true
        configuration.filterSockets = false
        configuration.filterPacketProviderBundleIdentifier = identifier
        configuration.vendorConfiguration = [
            "schemaVersion": 1,
            "expiresAt": expiresAt.timeIntervalSince1970,
            "endpointExceptions": endpoints.map {
                ["address": $0.address, "protocolNumber": $0.transport.rawValue, "port": Int($0.port)] as [String: Any]
            }
        ]
        return configuration
    }

    public static func providerBundleIdentifier(for applicationBundleIdentifier: String) throws -> String {
        let segments = applicationBundleIdentifier.split(separator: ".", omittingEmptySubsequences: false)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
        guard segments.count >= 2,
              segments.allSatisfy({ !$0.isEmpty && $0.unicodeScalars.allSatisfy(allowed.contains) }) else {
            throw ConfigurationError.invalidApplicationIdentifier
        }
        return applicationBundleIdentifier + ".NetworkGuard"
    }
}
#endif
