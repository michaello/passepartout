// SPDX-License-Identifier: GPL-3.0

import Foundation
import Network

// Standalone deterministic packet tests. These do not activate a host filter or
// establish any boot, crash, update, or physical-network leakage guarantee.
var checks = 0
@MainActor
func check(_ condition: @autoclosure () -> Bool, _ message: String) {
    precondition(condition(), message)
    checks += 1
}
func allows(_ policy: NetworkGuardPolicy, _ bytes: [UInt8], outbound: Bool = true) -> Bool {
    bytes.withUnsafeBytes { policy.allows($0, outbound: outbound) }
}
func writeWord(_ bytes: inout [UInt8], _ offset: Int, _ value: Int) {
    bytes[offset] = UInt8(value >> 8)
    bytes[offset + 1] = UInt8(value & 255)
}
func ethernet(_ payload: [UInt8], type: Int) -> [UInt8] {
    var header = Array(repeating: UInt8(0), count: 14)
    writeWord(&header, 12, type)
    return header + payload
}
func transport(proto: UInt8, source: Int = 50000, destination: Int = 1194) -> [UInt8] {
    var bytes = Array(repeating: UInt8(0), count: proto == 6 ? 20 : 8)
    writeWord(&bytes, 0, source)
    writeWord(&bytes, 2, destination)
    if proto == 6 { bytes[12] = 0x50 } else { writeWord(&bytes, 4, bytes.count) }
    return bytes
}
func ipv4(proto: UInt8 = 17, destination: String = "198.51.100.4", source: String = "192.0.2.2", sourcePort: Int = 50000, destinationPort: Int = 1194) -> [UInt8] {
    let body = transport(proto: proto, source: sourcePort, destination: destinationPort)
    var bytes = Array(repeating: UInt8(0), count: 20)
    bytes[0] = 0x45
    bytes[9] = proto
    writeWord(&bytes, 2, bytes.count + body.count)
    bytes.replaceSubrange(12..<16, with: IPv4Address(source)!.rawValue)
    bytes.replaceSubrange(16..<20, with: IPv4Address(destination)!.rawValue)
    return ethernet(bytes + body, type: 0x0800)
}
func ipv6(proto: UInt8 = 17, destination: String = "2001:db8::4", source: String = "2001:db8::2", body: [UInt8]? = nil) -> [UInt8] {
    let body = body ?? transport(proto: proto)
    var bytes = Array(repeating: UInt8(0), count: 40)
    bytes[0] = 0x60
    bytes[6] = proto
    bytes[7] = 255
    writeWord(&bytes, 4, body.count)
    bytes.replaceSubrange(8..<24, with: IPv6Address(source)!.rawValue)
    bytes.replaceSubrange(24..<40, with: IPv6Address(destination)!.rawValue)
    return ethernet(bytes + body, type: 0x86dd)
}

let endpoint = NetworkGuardPolicy.Endpoint(address: "198.51.100.4", protocolNumber: 17, port: 1194)!
let policy = NetworkGuardPolicy(endpoints: [endpoint])
let packet = ipv4()
check(allows(policy, packet), "Exact endpoint must be allowed")
check(!allows(.blockAll, packet), "Missing policy must not allow an endpoint")
check(!allows(policy, ipv4(destination: "198.51.100.5")), "Adjacent address must be blocked")
check(!allows(policy, ipv4(destinationPort: 443)), "Other port must be blocked")
check(!allows(policy, ipv4(proto: 6)), "Other transport must be blocked")
check(!allows(policy, ipv4(destination: "8.8.8.8", destinationPort: 53)), "Direct DNS must be blocked")
check(allows(policy, ipv4(destination: "192.0.2.2", source: "198.51.100.4", sourcePort: 1194, destinationPort: 50000), outbound: false), "Endpoint response must be allowed")
check(!allows(policy, ipv4(destination: "192.0.2.2", source: "198.51.100.5", sourcePort: 1194, destinationPort: 50000), outbound: false), "Other source response must be blocked")
for length in 0..<packet.count {
    check(!allows(policy, Array(packet.prefix(length))), "Truncated endpoint packet must be blocked")
}
var invalid = packet
invalid[20] = 0x20
check(!allows(policy, invalid), "First fragment must be blocked")
invalid = packet
invalid[20] = 0x80
check(!allows(policy, invalid), "Reserved fragmentation flag must be blocked")
invalid = packet
invalid[21] = 1
check(!allows(policy, invalid), "Later fragment must be blocked")
invalid = packet
invalid[14] = 0x44
check(!allows(policy, invalid), "Invalid IPv4 header length must be blocked")
invalid = packet
invalid[39] = 9
check(!allows(policy, invalid), "Truncated UDP payload must be blocked")
check(!allows(policy, Array(packet.dropFirst(14))), "Raw IP must not be mistaken for Ethernet")
var vlan = Array(packet.prefix(12)) + [UInt8(0x81), 0, 0, 1] + Array(packet.dropFirst(12))
check(allows(policy, vlan), "VLAN endpoint must be parsed")
vlan.insert(contentsOf: [0x88, 0xa8, 0, 2], at: 12)
check(allows(policy, vlan), "Double VLAN endpoint must be parsed")
vlan.insert(contentsOf: [0x81, 0, 0, 3], at: 12)
check(!allows(policy, vlan), "Unknown deeper encapsulation must be blocked")

let tcp = NetworkGuardPolicy(endpoints: [NetworkGuardPolicy.Endpoint(address: "198.51.100.4", protocolNumber: 6, port: 1194)!])
check(allows(tcp, ipv4(proto: 6)), "Exact TCP endpoint must be allowed")
invalid = ipv4(proto: 6)
invalid[46] = 0xf0
check(!allows(tcp, invalid), "Truncated TCP options must be blocked")
let v6 = NetworkGuardPolicy(endpoints: [NetworkGuardPolicy.Endpoint(address: "2001:db8::4", protocolNumber: 17, port: 1194)!])
check(allows(v6, ipv6()), "Exact IPv6 endpoint must be allowed")
check(!allows(v6, ipv6(destination: "2001:db8::5")), "Other IPv6 destination must be blocked")
invalid = ipv6()
invalid[20] = 44
check(!allows(v6, invalid), "IPv6 fragments must be blocked")
invalid[20] = 0
check(!allows(v6, invalid), "Unknown IPv6 extension headers must be blocked")

let now = Date().timeIntervalSince1970
let good: [String: Any] = ["schemaVersion": 1, "expiresAt": now + 60, "endpointExceptions": [["address": "198.51.100.4", "protocolNumber": 17, "port": 1194]]]
check(allows(NetworkGuardPolicy(configuration: good), packet), "Valid saved policy must load")
check(!allows(NetworkGuardPolicy(configuration: nil), packet), "Missing saved policy must block")
for field in ["schemaVersion", "expiresAt", "endpointExceptions"] {
    var missing = good
    missing.removeValue(forKey: field)
    check(!allows(NetworkGuardPolicy(configuration: missing), packet), "Incomplete policy must block")
}
var stale = good
stale["expiresAt"] = now - 1
check(!allows(NetworkGuardPolicy(configuration: stale), packet), "Expired policy must block")
stale = good
stale["schemaVersion"] = 2
check(!allows(NetworkGuardPolicy(configuration: stale), packet), "Unknown schema must block")
var partial = good
partial["endpointExceptions"] = [["address": "198.51.100.4", "protocolNumber": 17, "port": 1194], ["address": "vpn.example.com", "protocolNumber": 17, "port": 1194]]
check(!allows(NetworkGuardPolicy(configuration: partial), packet), "Partially invalid policy must block atomically")
check(NetworkGuardPolicy.Endpoint(address: "vpn.example.com", protocolNumber: 17, port: 1194) == nil, "Hostname endpoint must be rejected")
check(NetworkGuardPolicy.Endpoint(address: "198.51.100.4", protocolNumber: 1, port: 1194) == nil, "Unsupported endpoint transport must be rejected")
check(NetworkGuardPolicy.Endpoint(address: "198.51.100.4", protocolNumber: 17, port: 0) == nil, "Zero port must be rejected")

check(allows(.blockAll, ipv4(destination: "255.255.255.255", source: "0.0.0.0", sourcePort: 68, destinationPort: 67)), "DHCP broadcast must be allowed")
check(!allows(.blockAll, ipv4(destination: "198.51.100.4", sourcePort: 68, destinationPort: 67)), "DHCP port is not a general endpoint exception")
var nd = Array(repeating: UInt8(0), count: 24)
nd[0] = 135
nd.replaceSubrange(8..<24, with: IPv6Address("2001:db8::1")!.rawValue)
check(allows(.blockAll, ipv6(proto: 58, destination: "ff02::1:ff00:1", source: "fe80::2", body: nd)), "Link-local neighbor solicitation must be allowed")
check(!allows(.blockAll, ipv6(proto: 58, destination: "2001:db8::9", source: "fe80::2", body: nd)), "NS destination must match its target")
invalid = ipv6(proto: 58, destination: "ff02::1:ff00:1", source: "fe80::2", body: nd)
invalid[21] = 254
check(!allows(.blockAll, invalid), "Forwarded neighbor discovery must be blocked")
check(allows(.blockAll, ipv6(proto: 58, destination: "ff02::1:ff00:1", source: "2001:db8::2", body: nd)), "NS may use an assigned global source")
check(allows(.blockAll, ipv6(proto: 58, destination: "2001:db8::1", source: "2001:db8::2", body: nd)), "Unicast neighbor reachability probes must be allowed")
check(allows(.blockAll, ipv6(proto: 58, destination: "ff02::1:ff00:1", source: "::", body: nd)), "DAD must be allowed for the solicited-node group")
check(!allows(.blockAll, ipv6(proto: 58, destination: "2001:db8::1", source: "::", body: nd)), "DAD must not use unicast destination")
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::1:ff00:2", source: "::", body: nd)), "DAD must use the target's solicited-node group")
var malformedND = nd + [1, 1, 0, 0, 0, 0, 0, 0]
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::1:ff00:1", source: "::", body: malformedND)), "DAD must not claim a source link-layer address")
malformedND = nd + [1, 0]
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::1:ff00:1", source: "fe80::2", body: malformedND)), "Zero-length ND option must be blocked")
malformedND = nd + [1, 2, 0, 0, 0, 0, 0, 0]
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::1:ff00:1", source: "fe80::2", body: malformedND)), "Truncated ND option must be blocked")
malformedND = nd
malformedND.replaceSubrange(8..<24, with: IPv6Address("ff02::1")!.rawValue)
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::1", source: "fe80::2", body: malformedND)), "Multicast ND target must be blocked")
var na = nd
na[0] = 136
na[4] = 0x60
check(allows(.blockAll, ipv6(proto: 58, destination: "fe80::2", source: "2001:db8::1", body: na)), "NA must allow an assigned global source")
check(allows(.blockAll, ipv6(proto: 58, destination: "2001:db8::2", source: "2001:db8::1", body: na), outbound: false), "NA may be delivered to a global address on this link")
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::1", source: "2001:db8::1", body: na)), "Solicited NA must not use a multicast destination")
na[4] = 0x20
check(allows(.blockAll, ipv6(proto: 58, destination: "ff02::1", source: "2001:db8::1", body: na)), "Unsolicited NA to all-nodes must be allowed")
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::2", source: "2001:db8::1", body: na)), "NA must not use an unrelated multicast destination")
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::1", source: "::", body: na)), "NA must not have an unspecified source")
var rs = Array(repeating: UInt8(0), count: 8)
rs[0] = 133
check(allows(.blockAll, ipv6(proto: 58, destination: "ff02::2", source: "::", body: rs)), "Initial RS must be allowed")
check(!allows(.blockAll, ipv6(proto: 58, destination: "2001:db8::2", source: "::", body: rs)), "RS must not permit arbitrary global traffic")
var ra = Array(repeating: UInt8(0), count: 16)
ra[0] = 134
check(allows(.blockAll, ipv6(proto: 58, destination: "2001:db8::2", source: "fe80::1", body: ra), outbound: false), "Router may answer a global-source RS with a unicast RA")
check(!allows(.blockAll, ipv6(proto: 58, destination: "ff02::1", source: "2001:db8::1", body: ra)), "RA source must be link-local")
var redirect = Array(repeating: UInt8(0), count: 40)
redirect[0] = 137
check(!allows(.blockAll, ipv6(proto: 58, destination: "fe80::2", source: "fe80::1", body: redirect)), "Redirects remain blocked")
var echo = Array(repeating: UInt8(0), count: 8)
echo[0] = 128
check(!allows(.blockAll, ipv6(proto: 58, destination: "2001:db8::2", source: "2001:db8::1", body: echo)), "Ordinary ICMPv6 is not a maintenance exception")
var dhcp = transport(proto: 17, source: 546, destination: 547) + [1, 0, 0, 1]
writeWord(&dhcp, 4, dhcp.count)
check(allows(.blockAll, ipv6(destination: "ff02::1:2", source: "fe80::2", body: dhcp)), "DHCPv6 multicast Solicit must be allowed")
check(!allows(.blockAll, ipv6(destination: "2001:db8::9", source: "fe80::2", body: dhcp)), "DHCPv6 must not be a general global UDP exception")
check(!allows(.blockAll, ipv6(destination: "ff02::1:2", source: "2001:db8::2", body: dhcp)), "Initial DHCPv6 prototype requires a link-local client")
dhcp[8] = 5
check(allows(.blockAll, ipv6(destination: "fe80::1", source: "fe80::2", body: dhcp)), "DHCPv6 may renew with an on-link server")
writeWord(&dhcp, 0, 547)
writeWord(&dhcp, 2, 546)
dhcp[8] = 7
check(allows(.blockAll, ipv6(destination: "fe80::2", source: "fe80::1", body: dhcp), outbound: false), "DHCPv6 server Reply must be allowed")
check(!allows(.blockAll, ipv6(destination: "fe80::2", source: "2001:db8::1", body: dhcp), outbound: false), "Global DHCPv6 server traffic remains unsupported")
check(!allows(.blockAll, ipv6(destination: "2001:db8::2", source: "fe80::1", body: dhcp), outbound: false), "Global DHCPv6 client traffic remains unsupported")
check(!allows(.blockAll, ipv6(destination: "fe80::2", source: "fe80::1", body: dhcp)), "Outbound traffic cannot claim to be a DHCPv6 server Reply")
dhcp[8] = 1
check(!allows(.blockAll, ipv6(destination: "fe80::2", source: "fe80::1", body: dhcp), outbound: false), "Inbound client message is not a DHCPv6 reply")

// Deterministic malformed-frame fuzzing checks parser bounds without networking.
var state: UInt64 = 4
for length in 0..<256 {
    var bytes: [UInt8] = []
    for _ in 0..<length {
        state = state &* 6364136223846793005 &+ 1
        bytes.append(UInt8(truncatingIfNeeded: state >> 32))
    }
    _ = allows(policy, bytes)
    _ = allows(policy, bytes, outbound: false)
    checks += 2
}
print("NetworkGuardPolicy: \(checks) checks passed; no live enforcement or persistence claim")

if #available(macOS 27.0, *) {
    let endpoint = try NetworkGuardPrototypeConfiguration.Endpoint(address: "198.51.100.4", transport: .udp, port: 1194)
    let configuration = try NetworkGuardPrototypeConfiguration.make(endpoints: [endpoint], expiresAt: Date().addingTimeInterval(60))
    check(configuration.filterPackets && !configuration.filterSockets, "Prototype must request only packet filtering")
    check(configuration.filterPacketProviderBundleIdentifier == NetworkGuardPrototypeConfiguration.providerBundleIdentifier, "Prototype provider must be selected explicitly")
    check(allows(NetworkGuardPolicy(configuration: configuration.vendorConfiguration), packet), "Builder and provider schemas must interoperate")
    for invalidAddress in ["vpn.example.com", "", "198.51.100.999"] {
        do {
            _ = try NetworkGuardPrototypeConfiguration.Endpoint(address: invalidAddress, transport: .udp, port: 1194)
            preconditionFailure("Invalid endpoint accepted")
        } catch { checks += 1 }
    }
    do {
        _ = try NetworkGuardPrototypeConfiguration.make(endpoints: [], expiresAt: Date().addingTimeInterval(60))
        preconditionFailure("Empty configuration accepted")
    } catch { checks += 1 }
    do {
        _ = try NetworkGuardPrototypeConfiguration.make(endpoints: [endpoint], expiresAt: .distantPast)
        preconditionFailure("Expired configuration accepted")
    } catch { checks += 1 }
    print("NetworkGuard configuration builder: checks passed; total \(checks)")
}
