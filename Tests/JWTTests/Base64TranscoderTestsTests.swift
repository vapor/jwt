@testable import JWT
import XCTest

final class Base64TranscoderTests: XCTestCase {
    func testBase64ToBase64URL() {
        XCTAssertEqual(Base64URLTranscoder().base64URLEncode("abc+/==="), "abc-_")
    }

    func testBase64URLToBase64() {
        XCTAssertEqual(Base64URLTranscoder().base64Encode("abc-_"), "abc+/===")
    }

    func testZeroPadding() {
        XCTAssertEqual(Base64URLTranscoder().base64Encode("abcd"), "abcd")
    }

    static let all = [
        ("testBase64ToBase64URL", testBase64ToBase64URL),
        ("testBase64URLToBase64", testBase64URLToBase64),
        ("testZeroPadding", testZeroPadding)
    ]
}
