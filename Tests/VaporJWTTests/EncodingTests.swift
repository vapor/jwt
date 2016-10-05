@testable import VaporJWT
import JSON
import XCTest

// FIXME: Improve these tests with representative data
final class EncodingTests: XCTestCase {

    func testEncodeBase64() {
        let message = JSON(["a": .string("abc+-/_=")])
        XCTAssertEqual(try Encoding.base64.encode(message), "eyJhIjoiYWJjKy1cL189In0=")
    }

    func testEncodeBase64URL() {
        let message = JSON(["a": .string("abc+-/_=")])
        XCTAssertEqual(try Encoding.base64URL.encode(message), "eyJhIjoiYWJjKy1cL189In0")
    }

    func testDecodeBase64() {
        let message = "eyJhIjoiYWJjKy1cL189In0="
        XCTAssertEqual(try Encoding.base64.decode(message), JSON(["a": .string("abc+-/_=")]))
    }

    func testDecodeBase64URL() {
        let message = "eyJhIjoiYWJjKy1cL189In0="
        XCTAssertEqual(try Encoding.base64URL.decode(message), JSON(["a": .string("abc+-/_=")]))
    }

    static var all = [testEncodeBase64, testEncodeBase64URL, testDecodeBase64, testDecodeBase64URL]
}
