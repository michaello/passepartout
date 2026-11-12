// SPDX-License-Identifier: GPL-3.0

import XCTest

#if os(iOS)
/// Explicit physical-device diagnostics. Ordinary screenshot plans skip this test.
@MainActor
final class RequireVPNProfileUITests: XCTestCase {
    func testInspectSystem() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["REQUIRE_VPN_DEVICE_UI"] == "1")
        continueAfterFailure = false
        let system = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        saveEvidence("CurrentSystem", application: system)
    }

    func testInspectSettings() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["REQUIRE_VPN_DEVICE_UI"] == "1")
        continueAfterFailure = false
        let system = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        if system.alerts["Profile Downloaded"].exists {
            system.alerts["Profile Downloaded"].buttons["Close"].tap()
        }
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        XCTAssertTrue(settings.wait(for: .runningForeground, timeout: 15))
        waitForSettingsWindow(settings)
        saveEvidence("Settings", application: settings)
    }

    func testReviewPreflightProfile() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["REQUIRE_VPN_DEVICE_UI"] == "1")
        try XCTSkipIf((ProcessInfo.processInfo.environment["REQUIRE_VPN_PREFLIGHT_URL"] ?? "").isEmpty)
        continueAfterFailure = false
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        XCTAssertTrue(settings.wait(for: .runningForeground, timeout: 15))
        let name = settings.staticTexts["Require VPN preflight (no network changes)"]
        XCTAssertTrue(name.waitForExistence(timeout: 10))
        name.tap()
        XCTAssertTrue(settings.navigationBars["Install Profile"].waitForExistence(timeout: 5))
        waitForSettingsWindow(settings)
        saveEvidence("PreflightDetails", application: settings)
    }

    func testInstallPreflightProfile() throws {
        let environment = ProcessInfo.processInfo.environment
        try XCTSkipUnless(environment["REQUIRE_VPN_DEVICE_UI"] == "1")
        try XCTSkipUnless(environment["REQUIRE_VPN_INSTALL_PREFLIGHT"] == "1")
        continueAfterFailure = false
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        XCTAssertTrue(settings.wait(for: .runningForeground, timeout: 15))
        XCTAssertFalse(settings.secureTextFields["Passcode"].exists,
                       "Enter the passcode directly on the iPhone before resuming this test.")
        if settings.navigationBars["Warning"].exists {
            let message = settings.staticTexts.matching(NSPredicate(
                format: "label CONTAINS %@ AND label CONTAINS %@",
                "Require VPN preflight (no network changes)", "cannot be verified"
            )).firstMatch
            XCTAssertTrue(message.exists)
        } else {
            let install = settings.navigationBars["Install Profile"]
            XCTAssertTrue(install.waitForExistence(timeout: 5))
            XCTAssertTrue(settings.staticTexts["Require VPN preflight (no network changes)"].firstMatch.exists)
            XCTAssertTrue(settings.staticTexts["Temporary removable declaration test. No VPN, certificates, or restrictions."].exists)
            XCTAssertTrue(settings.staticTexts["Declaration"].exists)
            install.buttons["Install"].tap()
        }
        if settings.secureTextFields["Passcode"].exists {
            XCTFail("iOS requires the device owner to enter the passcode directly on the iPhone.")
            return
        }
        let confirmation = settings.alerts["Install Profile"]
        if !confirmation.exists {
            let warning = settings.navigationBars["Warning"]
            XCTAssertTrue(warning.waitForExistence(timeout: 5))
            saveEvidence("PreflightWarning", application: settings)
            warning.buttons["Install"].tap()
        }
        XCTAssertTrue(confirmation.waitForExistence(timeout: 5))
        saveEvidence("PreflightConfirmation", application: settings)
        confirmation.buttons["Install"].tap()
        saveEvidence("PreflightInstallResult", application: settings)
        XCTAssertTrue(settings.navigationBars["Profile Installed"].waitForExistence(timeout: 10))
        settings.navigationBars["Profile Installed"].buttons["Done"].tap()
        waitForSettingsWindow(settings)
        saveEvidence("PreflightInstalled", application: settings)
    }

    func testDownloadPreflightProfile() throws {
        continueAfterFailure = false
        let environment = ProcessInfo.processInfo.environment
        try XCTSkipUnless(environment["REQUIRE_VPN_DEVICE_UI"] == "1")
        let address = environment["REQUIRE_VPN_PREFLIGHT_URL"] ?? ""
        try XCTSkipIf(address.isEmpty, "Supply the harmless preflight profile URL explicitly.")
        let url = try XCTUnwrap(URL(string: address))
        XCTAssertTrue(["http", "https"].contains(url.scheme ?? ""))
        XCTAssertNotNil(url.host)
        XCTAssertEqual(url.pathExtension, "mobileconfig")
        let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
        safari.open(url)
        XCTAssertTrue(safari.wait(for: .runningForeground, timeout: 15))
        let allow = safari.buttons["Allow"]
        if allow.waitForExistence(timeout: 15) {
            saveEvidence("DownloadConsent", application: safari)
            allow.tap()
        }
        finishDownload()
    }

    func testRemoveDownloadedPreflightProfile() throws {
        let environment = ProcessInfo.processInfo.environment
        try XCTSkipUnless(environment["REQUIRE_VPN_DEVICE_UI"] == "1")
        try XCTSkipIf((environment["REQUIRE_VPN_PREFLIGHT_URL"] ?? "").isEmpty)
        continueAfterFailure = false
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        XCTAssertTrue(settings.wait(for: .runningForeground, timeout: 15))
        if !settings.navigationBars["Install Profile"].exists {
            let name = settings.tables.staticTexts["Require VPN preflight (no network changes)"]
            XCTAssertTrue(name.waitForExistence(timeout: 5))
            name.tap()
        }
        XCTAssertTrue(settings.navigationBars["Install Profile"].waitForExistence(timeout: 5))
        XCTAssertTrue(settings.staticTexts["Temporary removable declaration test. No VPN, certificates, or restrictions."].exists)
        settings.tables.staticTexts["Remove Downloaded Profile"].tap()
        XCTAssertTrue(settings.navigationBars["Install Profile"].waitForNonExistence(timeout: 5))
        XCTAssertFalse(settings.tables.staticTexts["Require VPN preflight (no network changes)"].exists)
        waitForSettingsWindow(settings)
        saveEvidence("DownloadedPreflightRemoved", application: settings)
    }

    private func finishDownload() {
        let system = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        saveEvidence("SystemDialog", application: system)
        let phone = system.buttons["iPhone"]
        if phone.waitForExistence(timeout: 3) { phone.tap() }
        let downloaded = system.staticTexts["Profile Downloaded"]
        XCTAssertTrue(downloaded.waitForExistence(timeout: 10))
        saveEvidence("DownloadConfirmed", application: system)
        system.buttons["Close"].tap()
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        XCTAssertTrue(settings.wait(for: .runningForeground, timeout: 15))
        waitForSettingsWindow(settings)
        let name = settings.tables.staticTexts["Require VPN preflight (no network changes)"]
        if !name.waitForExistence(timeout: 3), settings.navigationBars["VPN & Device Management"].exists {
            settings.navigationBars.buttons["BackButton"].tap()
            XCTAssertTrue(settings.navigationBars["General"].waitForExistence(timeout: 5))
            let management = settings.tables.staticTexts["VPN & Device Management"]
            for _ in 0..<4 where !management.isHittable { settings.swipeUp() }
            XCTAssertTrue(management.waitForExistence(timeout: 3))
            management.tap()
        }
        waitForSettingsWindow(settings)
        saveEvidence("AfterDownload", application: settings)
        XCTAssertTrue(name.waitForExistence(timeout: 10))
    }

    private func waitForSettingsWindow(_ settings: XCUIApplication) {
        let settled = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            settings.windows.firstMatch.frame.origin == .zero
        }, object: settings)
        XCTAssertEqual(XCTWaiter.wait(for: [settled], timeout: 5), .completed)
    }

    private func saveEvidence(_ name: String, application: XCUIApplication) {
        let screenshot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        screenshot.name = "RequireVPN-\(name)"
        screenshot.lifetime = .keepAlways
        add(screenshot)
        let hierarchy = XCTAttachment(string: application.debugDescription)
        hierarchy.name = "RequireVPN-\(name)-hierarchy"
        hierarchy.lifetime = .keepAlways
        add(hierarchy)
    }
}
#endif
