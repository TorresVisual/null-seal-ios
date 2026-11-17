import XCTest
@testable import NullSeal

final class CoreRoundTripTests: XCTestCase {
    func testCoreCallRoundTrips() throws {
        XCTAssertFalse(coreVersion().isEmpty)
        let pw = try generatePassword(length: 24)
        XCTAssertEqual(pw.count, 24)
        XCTAssertEqual(estimateStrength(password: "password"), 0)
        XCTAssertThrowsError(try generatePassword(length: 0))
    }
}
