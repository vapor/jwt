@testable import VaporJWT
import XCTest

final class Base64Tests: XCTestCase {

    func testBase64ToBase64URL() {
        XCTAssertEqual("abc+/===".base64URL, "abc-_")
    }

    func testBase64URLToBase64() {
        XCTAssertEqual("abc-_".base64, "abc+/===")
    }

    static var all = [testBase64ToBase64URL, testBase64URLToBase64]
}
