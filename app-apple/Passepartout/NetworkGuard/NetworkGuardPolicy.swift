// SPDX-License-Identifier: GPL-3.0

import Foundation
import Network

/// Stage-one packet-filter prototype. There is deliberately no trusted utun or
/// connected-VPN bypass. Authorizing inner traffic requires measured visibility
/// and an authenticated tunnel binding before this can be a usable product.
struct NetworkGuardPolicy {
    struct Endpoint {
        let address: Data
        let protocolNumber: UInt8
        let port: UInt16

        init?(address: String, protocolNumber: UInt8, port: UInt16) {
            guard [6, 17].contains(protocolNumber), port != 0,
                  let bytes = IPv4Address(address)?.rawValue ?? IPv6Address(address)?.rawValue else {
                return nil
            }
            self.address = bytes
            self.protocolNumber = protocolNumber
            self.port = port
        }
    }

    let endpoints: [Endpoint]

    private let expiresAt: Date

    static let blockAll = NetworkGuardPolicy(endpoints: [])

    /// Read only the OS-saved filter configuration. A missing, unknown, expired,
    /// or partially invalid policy grants no endpoint exceptions.
    init(configuration: [String: Any]?, now: Date = Date()) {
        guard let configuration,
              configuration["schemaVersion"] as? Int == 1,
              let expiresAt = configuration["expiresAt"] as? Double,
              expiresAt.isFinite, expiresAt > now.timeIntervalSince1970,
              let entries = configuration["endpointExceptions"] as? [[String: Any]],
              !entries.isEmpty, entries.count <= 32 else {
            endpoints = []
            self.expiresAt = .distantPast
            return
        }
        var decoded: [Endpoint] = []
        for entry in entries {
            guard let address = entry["address"] as? String,
                  let number = entry["protocolNumber"] as? Int,
                  let protocolNumber = UInt8(exactly: number),
                  let portNumber = entry["port"] as? Int,
                  let port = UInt16(exactly: portNumber),
                  let endpoint = Endpoint(address: address, protocolNumber: protocolNumber, port: port) else {
                endpoints = []
                self.expiresAt = .distantPast
                return
            }
            decoded.append(endpoint)
        }
        endpoints = decoded
        self.expiresAt = Date(timeIntervalSince1970: expiresAt)
    }

    init(endpoints: [Endpoint]) {
        self.endpoints = endpoints
        expiresAt = .distantFuture
    }

    /// NEFilterPacketProvider supplies layer-two frames. Unknown encapsulations,
    /// IP fragments and IPv6 extension headers fail closed in this prototype.
    func allows(_ frame: UnsafeRawBufferPointer, outbound: Bool) -> Bool {
        guard frame.count >= 14 else { return false }
        var type = word(frame, 12)
        var offset = 14
        for _ in 0..<2 where type == 0x8100 || type == 0x88a8 {
            guard frame.count >= offset + 4 else { return false }
            type = word(frame, offset + 2)
            offset += 4
        }
        if type == 0x0806 {
            // Ethernet/IPv4 ARP request or reply, including Ethernet padding.
            return frame.count >= offset + 28 && frame.count <= offset + 46
                && word(frame, offset) == 1 && word(frame, offset + 2) == 0x0800
                && frame[offset + 4] == 6 && frame[offset + 5] == 4
                && [1, 2].contains(word(frame, offset + 6))
        }
        let bytes = UnsafeRawBufferPointer(rebasing: frame[offset...])
        switch type {
        case 0x0800: return allowsIPv4(bytes, outbound: outbound)
        case 0x86dd: return allowsIPv6(bytes, outbound: outbound)
        default: return false
        }
    }

    private func allowsIPv4(_ bytes: UnsafeRawBufferPointer, outbound: Bool) -> Bool {
        guard bytes.count >= 20, bytes[0] >> 4 == 4 else { return false }
        let headerLength = Int(bytes[0] & 15) * 4
        let length = Int(word(bytes, 2))
        guard headerLength == 20, length >= headerLength, bytes.count >= length,
              word(bytes, 6) & 0xbfff == 0 else { return false }
        let packet = UnsafeRawBufferPointer(rebasing: bytes[..<length])
        let transport = UnsafeRawBufferPointer(rebasing: packet[headerLength...])
        let proto = bytes[9]
        guard validTransport(transport, protocolNumber: proto) else { return false }
        if proto == 17 {
            // DHCPv4 client/server only. Broadcast request or local server reply.
            let sourcePort = word(transport, 0)
            let destinationPort = word(transport, 2)
            if outbound && sourcePort == 68 && destinationPort == 67
                && Array(bytes[16..<20]) == [255, 255, 255, 255] { return true }
            if !outbound && sourcePort == 67 && destinationPort == 68 { return true }
        }
        let address = Data(bytes[(outbound ? 16 : 12)..<(outbound ? 20 : 16)])
        return matches(address, protocolNumber: proto, port: word(transport, outbound ? 2 : 0))
    }

    private func allowsIPv6(_ bytes: UnsafeRawBufferPointer, outbound: Bool) -> Bool {
        guard bytes.count >= 40, bytes[0] >> 4 == 6 else { return false }
        let length = 40 + Int(word(bytes, 4))
        guard length > 40, bytes.count >= length else { return false }
        let packet = UnsafeRawBufferPointer(rebasing: bytes[..<length])
        let transport = UnsafeRawBufferPointer(rebasing: packet[40...])
        let proto = bytes[6]
        if proto == 58 {
            // Neighbor discovery never forwards beyond this link (hop limit 255).
            // Redirects are not permitted. Require the standard fixed header size.
            let minimumLengths: [UInt8: Int] = [133: 8, 134: 16, 135: 24, 136: 24]
            guard transport.count >= 8, bytes[7] == 255, transport[1] == 0,
                  let minimum = minimumLengths[transport[0]], transport.count >= minimum else { return false }
            let sourceLinkLocal = bytes[8] == 0xfe && bytes[9] & 0xc0 == 0x80
            let sourceUnspecified = bytes[8..<24].allSatisfy { $0 == 0 }
            let destinationOnLink = bytes[24] == 0xff && bytes[25] == 0x02
                || bytes[24] == 0xfe && bytes[25] & 0xc0 == 0x80
            return destinationOnLink && (sourceLinkLocal || sourceUnspecified && [133, 135].contains(transport[0]))
        }
        guard validTransport(transport, protocolNumber: proto) else { return false }
        if proto == 17 && outbound && word(transport, 0) == 546 && word(transport, 2) == 547 {
            let dhcpMulticast: [UInt8] = [0xff, 0x02] + Array(repeating: 0, count: 11) + [1, 0, 2]
            if Array(bytes[24..<40]) == dhcpMulticast { return true }
        }
        let address = Data(bytes[(outbound ? 24 : 8)..<(outbound ? 40 : 24)])
        return matches(address, protocolNumber: proto, port: word(transport, outbound ? 2 : 0))
    }

    private func validTransport(_ bytes: UnsafeRawBufferPointer, protocolNumber: UInt8) -> Bool {
        switch protocolNumber {
        case 6:
            guard bytes.count >= 20 else { return false }
            let headerLength = Int(bytes[12] >> 4) * 4
            return headerLength >= 20 && headerLength <= bytes.count
        case 17:
            guard bytes.count >= 8 else { return false }
            return word(bytes, 4) >= 8 && Int(word(bytes, 4)) == bytes.count
        default: return false
        }
    }

    private func matches(_ address: Data, protocolNumber: UInt8, port: UInt16) -> Bool {
        guard Date() < expiresAt else { return false }
        return endpoints.contains { $0.address == address && $0.protocolNumber == protocolNumber && $0.port == port }
    }

    private func word(_ bytes: UnsafeRawBufferPointer, _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
}
