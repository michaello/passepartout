// SPDX-FileCopyrightText: 2026 Davide De Rosa
//
// SPDX-License-Identifier: GPL-3.0

import CommonLibrary
import Foundation
import Partout
import Testing

@MainActor
struct NetworkProtectionTests {
    private enum Failure: Error { case unavailable }

    private func temporaryStore() -> LocalNetworkProtectionPolicyStore {
        LocalNetworkProtectionPolicyStore(url: FileManager.default.temporaryDirectory
            .appendingPathComponent("require-vpn-\(UUID())", isDirectory: true)
            .appendingPathComponent("policy.plist"))
    }

    @Test
    func policyPersistsAcrossCoordinatorInstancesAndIsExcludedFromBackup() throws {
        let store = temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        #expect(try store.load() == .disabled)
        try store.save(.requireVPN)
        let restarted = NetworkProtectionCoordinator(store: store)
        #expect(restarted.policy == .requireVPN)
        #expect(restarted.enforcement == .unavailable)
        #expect(restarted.status == .protectionUnavailable)
        let values = try store.url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        #expect(values.isExcludedFromBackup == true)
        let attributes = try FileManager.default.attributesOfItem(atPath: store.url.path)
        #expect(attributes[.posixPermissions] as? Int == 0o600)
    }

    @Test
    func corruptPolicyNeverBecomesPermissionToBypass() throws {
        let store = temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        try store.save(.requireVPN)
        try Data("corrupt".utf8).write(to: store.url)
        #expect(throws: (any Error).self) { try store.load() }
        let coordinator = NetworkProtectionCoordinator(store: store)
        #expect(coordinator.policy == .requireVPN)
        #expect(coordinator.enforcement == .failed)
        coordinator.updateTunnel(.connected)
        #expect(coordinator.status == .protectionUnavailable)
    }

    @Test
    func failedActivationRetainsIntentAndDoesNotClaimBlocking() async throws {
        let store = temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        let coordinator = NetworkProtectionCoordinator(store: store)
        await #expect(throws: Failure.self) {
            try await coordinator.requireVPN {
                #expect(try store.load() == .requireVPN)
                throw Failure.unavailable
            }
        }
        #expect(coordinator.policy == .requireVPN)
        #expect(coordinator.enforcement == .failed)
        #expect(coordinator.status == .protectionUnavailable)
        #expect(try store.load() == .requireVPN)
    }

    @Test
    func connectedTunnelDoesNotArmGuardAndArmedGuardBlocksWhenDisconnected() async throws {
        let store = temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        let coordinator = NetworkProtectionCoordinator(store: store)
        try await coordinator.requireVPN {
            #expect(coordinator.enforcement == .installing)
            #expect(coordinator.status == .protectionUnavailable)
        }
        #expect(coordinator.status == .networkBlocked)
        coordinator.updateTunnel(.connected)
        #expect(coordinator.status == .vpnConnected)
        coordinator.updateTunnel(.reconnecting)
        #expect(coordinator.policy == .requireVPN)
        #expect(coordinator.status == .networkBlocked)
    }

    @Test
    func disablingRequiresConfirmationAndCannotRaceActivation() async throws {
        let store = temporaryStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        let coordinator = NetworkProtectionCoordinator(store: store)
        try await coordinator.requireVPN {
            await #expect(throws: NetworkProtectionCoordinator.TransitionError.operationInProgress) {
                try await coordinator.allowUnprotectedInternet(confirmed: true) {
                    Issue.record("Concurrent disable must not reach enforcement")
                }
            }
        }
        await #expect(throws: NetworkProtectionCoordinator.TransitionError.confirmationRequired) {
            try await coordinator.allowUnprotectedInternet(confirmed: false) {
                Issue.record("Unconfirmed disable must not reach enforcement")
            }
        }
        #expect(try store.load() == .requireVPN)
        try await coordinator.allowUnprotectedInternet(confirmed: true) { () async throws in
            #expect(try store.load() == .disabled)
        }
        #expect(coordinator.status == .unprotected)
    }
}
