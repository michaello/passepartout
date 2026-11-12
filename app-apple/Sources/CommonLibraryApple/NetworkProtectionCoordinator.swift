// SPDX-FileCopyrightText: 2026 Davide De Rosa
//
// SPDX-License-Identifier: GPL-3.0

import Observation
import Partout

/// Saved intent, verified enforcement, and tunnel reachability are separate facts.
/// No production arming driver is supplied until the platform acceptance tests pass.
@MainActor @Observable
public final class NetworkProtectionCoordinator {
    public enum Enforcement: Sendable {
        case unavailable
        case installing
        case armed
        case failed
    }

    public enum Tunnel: Sendable {
        case disconnected
        case connecting
        case connected
        case reconnecting
    }

    public enum Status: Sendable {
        case unprotected
        case vpnConnected
        case networkBlocked
        case protectionUnavailable
    }

    public enum TransitionError: Error {
        case operationInProgress
        case confirmationRequired
    }

    public private(set) var policy: NETunnelProtection
    public private(set) var enforcement: Enforcement = .unavailable
    public private(set) var tunnel: Tunnel = .disconnected
    public private(set) var lastError: (any Error)?
    private let persistPolicy: @MainActor (NETunnelProtection) async throws -> Void
    private var isUpdating = false

    public init(
        store: any NetworkProtectionPolicyStoring,
        persistPolicy: (@MainActor (NETunnelProtection) async throws -> Void)? = nil
    ) {
        self.persistPolicy = persistPolicy ?? { try store.save($0) }
        do {
            policy = try store.load()
        } catch {
            // A corrupt or unreadable policy must never mean permission to bypass.
            policy = .requireVPN
            enforcement = .failed
            lastError = error
        }
    }

    public var status: Status {
        guard policy == .requireVPN else {
            return tunnel == .connected ? .vpnConnected : .unprotected
        }
        guard enforcement == .armed else { return .protectionUnavailable }
        return tunnel == .connected ? .vpnConnected : .networkBlocked
    }

    public func updateTunnel(_ tunnel: Tunnel) {
        self.tunnel = tunnel
    }

    /// The driver must verify active platform enforcement, not just saved preferences.
    public func requireVPN(verifyAndArm: @MainActor () async throws -> Void) async throws {
        guard !isUpdating else { throw TransitionError.operationInProgress }
        isUpdating = true
        defer { isUpdating = false }
        policy = .requireVPN
        do {
            try await persistPolicy(.requireVPN)
            enforcement = .installing
            lastError = nil
            try await verifyAndArm()
            try Task.checkCancellation()
            enforcement = .armed
        } catch {
            enforcement = .failed
            lastError = error
            throw error
        }
    }

    /// Only an explicit user action may call this operation. Failures never call it.
    public func allowUnprotectedInternet(
        confirmed: Bool,
        disableEnforcement: @MainActor () async throws -> Void
    ) async throws {
        guard confirmed else { throw TransitionError.confirmationRequired }
        guard !isUpdating else { throw TransitionError.operationInProgress }
        isUpdating = true
        defer { isUpdating = false }
        do {
            // The strict manager marker still prevents ordinary disconnects.
            // The driver must use the explicit NE disable-protection operation.
            try await persistPolicy(.disabled)
            policy = .disabled
            try await disableEnforcement()
            enforcement = .unavailable
            lastError = nil
        } catch {
            enforcement = .failed
            lastError = error
            throw error
        }
    }
}
