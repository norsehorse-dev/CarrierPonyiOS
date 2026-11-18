// SnapshotTests.swift
// CarrierPony iOS
//
// Store screenshots, driven by fastlane snapshot (fastlane/Snapfile). Each
// screen is a fresh launch with -demoSeed (seed fictional demo data, stay off
// the network) and -demoScreen (which screen to open); see DemoSeed.swift in
// the app target. No taps on localized UI, so every language runs the same.

import XCTest

final class SnapshotTests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testCaptureScreenshots() throws {
        let screens = [("01Inbox", "inbox"), ("02Chat", "chat"), ("03Group", "group"), ("04Files", "files"), ("05Pair", "pair")]
        for (name, screen) in screens {
            let app = XCUIApplication()
            setupSnapshot(app)
            app.launchArguments += ["-demoSeed", "-demoScreen", screen]
            app.launch()
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 20), "app did not launch for \(screen)")
            sleep(3)
            snapshot(name, timeWaitingForIdle: 5)
        }
    }
}
