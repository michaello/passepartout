// SPDX-FileCopyrightText: 2026 Davide De Rosa
//
// SPDX-License-Identifier: GPL-3.0

import Foundation
import Partout

public protocol NetworkProtectionPolicyStoring: Sendable {
    func load() throws -> NETunnelProtection
    func save(_ policy: NETunnelProtection) throws
}

/// Device policy is deliberately outside profile repositories and CloudKit.
public struct LocalNetworkProtectionPolicyStore: NetworkProtectionPolicyStoring {
    public enum StorageError: Error {
        case invalidPolicy
    }

    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    public init(applicationIdentifier: String) {
        url = URL.applicationSupportDirectory
            .appendingPathComponent(applicationIdentifier, isDirectory: true)
            .appendingPathComponent("NetworkProtection", isDirectory: true)
            .appendingPathComponent("policy.plist")
    }

    public func load() throws -> NETunnelProtection {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch CocoaError.fileReadNoSuchFile {
            // First installation only. Saved strict VPN configurations retain
            // their own marker even if the application policy file is missing.
            return .disabled
        }
        guard let payload = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              payload["version"] as? Int == 1,
              let rawValue = payload["policy"] as? String,
              let policy = NETunnelProtection(rawValue: rawValue) else {
            throw StorageError.invalidPolicy
        }
        return policy
    }

    public func save(_ policy: NETunnelProtection) throws {
        var directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try directory.setResourceValues(values)
        let data = try PropertyListSerialization.data(
            fromPropertyList: ["version": 1, "policy": policy.rawValue],
            format: .binary,
            options: 0
        )
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        var policyURL = url
        try policyURL.setResourceValues(values)
        guard try load() == policy else {
            throw StorageError.invalidPolicy
        }
    }
}
