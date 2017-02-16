@testable import JWT
import Core
import Node
import XCTest

private struct TestBase64URLTranscoder: Base64URLTranscoding {
    fileprivate func base64Encode(_: String) -> String? {
        return nil
    }

    fileprivate func base64URLEncode(_: String) -> String? {
        return nil
    }
}

final class EncodingTests: XCTestCase {
    let valueB64 = "////++++abc="
    let valueB64URL = "____----abc"

    func testBase64ToBase64URL() throws {
        let valueB64Bytes = try Base64Encoding().decode(valueB64) as Bytes
        XCTAssertEqual(try Base64URLEncoding().encode(valueB64Bytes), valueB64URL)
    }

    func testBase64URLToBase64() throws {
        let valueB64URLBytes = try Base64URLEncoding().decode(valueB64URL) as Bytes
        XCTAssertEqual(try Base64Encoding().encode(valueB64URLBytes), valueB64)
    }

    func testBase64DecodeIgnoresErrorForInvalidString() throws {
        _ = try Base64Encoding().decode("\0")
    }

    func testBase64URLEncodeThrowsErrorForInvalidString() {
        XCTAssertThrowsError(
            try Base64URLEncoding(
                base64URLTranscoder: TestBase64URLTranscoder()
            ).encode("")
        ) {
            guard let error = $0 as? JWTError, case .encoding = error else {
                XCTFail("Wrong error: \($0)")
                return
            }
        }
    }

    func testBase64URLDecodeThrowsErrorForInvalidString() {
        XCTAssertThrowsError(
            try Base64URLEncoding(
                base64URLTranscoder: TestBase64URLTranscoder()
            ).decode("")
        ) {
            guard let error = $0 as? JWTError, case .decoding = error else {
                XCTFail("Wrong error: \($0)")
                return
            }
        }
    }

    static let all = [
        ("testBase64ToBase64URL", testBase64ToBase64URL),
        ("testBase64URLToBase64", testBase64URLToBase64),
        ("testBase64DecodeIgnoresErrorForInvalidString", testBase64DecodeIgnoresErrorForInvalidString),
        ("testBase64URLEncodeThrowsErrorForInvalidString", testBase64URLEncodeThrowsErrorForInvalidString),
        ("testBase64URLDecodeThrowsErrorForInvalidString", testBase64URLDecodeThrowsErrorForInvalidString),
    ]
}
