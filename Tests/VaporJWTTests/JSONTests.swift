@testable import VaporJWT
import JSON
import XCTest

class JSONTests: XCTestCase {

    func testDecode() {
        XCTAssertEqual(try JSON(base64Encoded: "eyJhIjoiYiJ9"), testMessage)
    }

    func testNotBase64Encoded() {
        XCTAssertTrue(throwsError(
            .notBase64Encoded,
            for: try JSON(base64Encoded: "0")))
    }

    static var all = [testDecode, testNotBase64Encoded]
}
