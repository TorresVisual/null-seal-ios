import XCTest
@testable import NullSeal

final class CoreRoundTripTests: XCTestCase {
    func testAutoLockExpiry() {
        let t = Date(timeIntervalSince1970: 1_000_000)
        let limit = AppSession.autoLockAfter
        XCTAssertFalse(AppSession.autoLockExpired(since: nil, now: t))
        XCTAssertFalse(AppSession.autoLockExpired(since: t, now: t.addingTimeInterval(limit - 1)))
        XCTAssertTrue(AppSession.autoLockExpired(since: t, now: t.addingTimeInterval(limit)))
    }

    func testCoreCallRoundTrips() throws {
        XCTAssertFalse(coreVersion().isEmpty)
        let pw = try generatePassword(length: 24)
        XCTAssertEqual(pw.count, 24)
        XCTAssertEqual(estimateStrength(password: "password"), 0)
        XCTAssertThrowsError(try generatePassword(length: 0))
    }
}
