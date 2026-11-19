import XCTest

/// Walks the real app through its core flows against the local stand-in relay (`ui_relay`, started
/// by `ios/scripts/test-ui.sh`), taking a screenshot at each step. One test, because the steps
/// build on each other: the vault joined in step 1 is what the later steps unlock and edit.
final class VaultFlowTests: XCTestCase {
    private let app = XCUIApplication()

    private func env(_ key: String) throws -> String {
        try XCTUnwrap(ProcessInfo.processInfo.environment[key], "\(key) not set; run ios/scripts/test-ui.sh")
    }

    private func shot(_ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    private func appears(_ element: XCUIElement, _ what: String, timeout: TimeInterval = 30) {
        XCTAssertTrue(element.waitForExistence(timeout: timeout), "\(what) did not appear")
    }

    private func type(_ text: String, into field: XCUIElement) {
        field.tap()
        field.typeText(text)
    }

    func testJoinUnlockBrowseEditAndLock() throws {
        let relay = try env("NS_UI_RELAY"), code = try env("NS_UI_CODE"), password = try env("NS_UI_PASSWORD")
        continueAfterFailure = false
        app.launch()

        // 1. Join: the stand-in relay approves the request, the app stores the vault.
        appears(app.buttons["join"], "onboarding")
        shot("01-onboarding")
        type(relay, into: app.textFields["relay"])
        type(code, into: app.textFields["code"])
        shot("02-join-filled")
        app.buttons["join"].tap()

        // 2. Unlock with the master password; the first sync pulls the two seeded logins.
        appears(app.secureTextFields["password"], "unlock screen", timeout: 90)
        shot("03-unlock")
        type(password, into: app.secureTextFields["password"])
        app.buttons["unlock"].tap()
        let notNow = app.alerts.buttons["Not now"]  // only where the simulator offers biometrics
        if notNow.waitForExistence(timeout: 5) { notNow.tap() }

        // 3. List.
        appears(app.staticTexts["Bank"], "synced list")
        XCTAssertTrue(app.staticTexts["Email"].exists)
        XCTAssertEqual(app.staticTexts["items"].label, "2 items")
        shot("04-list")

        // 4. Search narrows the list.
        let search = app.searchFields.firstMatch
        type("Bank", into: search)
        XCTAssertTrue(app.staticTexts["Bank"].exists)
        XCTAssertFalse(app.staticTexts["Email"].exists)
        shot("05-search")
        // iOS 26 has no "Cancel" button, only an X; clear the text first, then close the search
        search.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: "Bank".count))
        appears(app.staticTexts["Email"], "full list after clearing the search")
        // an active search hides the toolbar's Add button; the X is labelled "close"
        app.buttons["close"].tap()

        // 5. Detail: the password stays hidden until revealed.
        app.staticTexts["Bank"].tap()
        appears(app.buttons["Show"], "item detail")
        XCTAssertFalse(app.staticTexts["hunter2-hunter2"].exists)
        app.buttons["Show"].tap()
        appears(app.staticTexts["hunter2-hunter2"], "revealed password", timeout: 5)
        shot("06-detail")
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // 6. Add a login.
        app.buttons["Add"].tap()
        type("UI test login", into: app.textFields["Title"])
        type("tester", into: app.textFields["Username"])
        shot("07-add")
        app.buttons["Save"].tap()
        appears(app.staticTexts["UI test login"], "new item in the list")
        XCTAssertEqual(app.staticTexts["items"].label, "3 items")
        shot("08-list-after-add")

        // 7. Delete it again.
        app.staticTexts["UI test login"].tap()
        appears(app.buttons["Edit"], "new item detail")
        app.buttons["Edit"].tap()
        appears(app.buttons["delete"], "edit screen")
        app.buttons["delete"].tap()
        // the dialog's own button; the form's is "delete" by identifier but shares the label
        let confirm = app.buttons.matching(NSPredicate(format: "label == 'Delete' AND identifier != 'delete'")).firstMatch
        appears(confirm, "delete confirmation", timeout: 5)
        confirm.tap()
        appears(app.staticTexts["items"], "list after delete")
        XCTAssertFalse(app.staticTexts["UI test login"].exists)
        XCTAssertEqual(app.staticTexts["items"].label, "2 items")
        shot("09-list-after-delete")

        // 8. Lock returns to the unlock screen.
        app.buttons["Lock"].tap()
        appears(app.secureTextFields["password"], "unlock screen after lock", timeout: 10)
        shot("10-locked")
    }
}
