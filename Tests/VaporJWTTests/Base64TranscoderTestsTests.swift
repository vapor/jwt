@testable import VaporJWT
import XCTest

final class Base64TranscoderTests: XCTestCase {

    func testBase64ToBase64URL() {
        XCTAssertEqual(Base64URLTranscoder().base64URLEncode("abc+/==="), "abc-_")
    }

    func testBase64URLToBase64() {
        XCTAssertEqual(Base64URLTranscoder().base64Encode("abc-_"), "abc+/===")
    }

    static var all = [
        testBase64ToBase64URL,
        testBase64URLToBase64
    ]
}
