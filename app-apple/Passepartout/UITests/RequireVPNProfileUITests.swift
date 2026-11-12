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
        let install = settings.navigationBars["Install Profile"]
        XCTAssertTrue(install.waitForExistence(timeout: 5))
        XCTAssertTrue(settings.staticTexts["Require VPN preflight (no network changes)"].firstMatch.exists)
        XCTAssertTrue(settings.staticTexts["Temporary removable declaration test. No VPN, certificates, or restrictions."].exists)
        XCTAssertTrue(settings.staticTexts["Declaration"].exists)
        if install.buttons["Install"].isHittable {
            install.buttons["Install"].tap()
        }
        if settings.secureTextFields["Passcode"].exists {
            XCTFail("iOS requires the device owner to enter the passcode directly on the iPhone.")
            return
        }
        for _ in 0..<3 {
            if settings.navigationBars["Profile Installed"].exists { break }
            if settings.navigationBars["Warning"].waitForExistence(timeout: 3) {
                saveEvidence("PreflightWarning", application: settings)
                settings.navigationBars["Warning"].buttons["Install"].tap()
            } else if settings.sheets.buttons["Install"].exists {
                settings.sheets.buttons["Install"].tap()
            } else {
                break
            }
        }
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
        if settings.navigationBars["VPN & Device Management"].exists {
            settings.navigationBars.buttons["BackButton"].tap()
            let management = settings.staticTexts["VPN & Device Management"]
            for _ in 0..<4 where !management.isHittable { settings.swipeUp() }
            XCTAssertTrue(management.waitForExistence(timeout: 3))
            management.tap()
        }
        waitForSettingsWindow(settings)
        saveEvidence("AfterDownload", application: settings)
        XCTAssertTrue(settings.staticTexts["Require VPN preflight (no network changes)"].waitForExistence(timeout: 10))
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
