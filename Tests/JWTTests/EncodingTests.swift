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
    let valueB64 = "eyAibXNnX2VuIjogIkhlbGxvIiwKICAibXNnX2pwIjogIuOBk+OCk+OBq+OBoeOBryIsCiAgIm1zZ19jbiI6ICLkvaDlpb0iLAogICJtc2dfa3IiOiAi7JWI64WV7ZWY7IS47JqUIiwKICAibXNnX3J1IjogItCX0LTRgNCw0LLRgdGC0LLRg9C50YLQtSEiLAogICJtc2dfZGUiOiAiR3LDvMOfIEdvdHQiIH0="
    let valueB64URL = "eyAibXNnX2VuIjogIkhlbGxvIiwKICAibXNnX2pwIjogIuOBk-OCk-OBq-OBoeOBryIsCiAgIm1zZ19jbiI6ICLkvaDlpb0iLAogICJtc2dfa3IiOiAi7JWI64WV7ZWY7IS47JqUIiwKICAibXNnX3J1IjogItCX0LTRgNCw0LLRgdGC0LLRg9C50YLQtSEiLAogICJtc2dfZGUiOiAiR3LDvMOfIEdvdHQiIH0"

    func testBase64ToBase64URL() {
        do {
            let valueB64Bytes = try Base64Encoding().decode(valueB64) as Bytes
            XCTAssertEqual(try Base64URLEncoding().encode(valueB64Bytes), valueB64URL)
        } catch {
            XCTFail("\(error)")
        }
    }

    func testBase64URLToBase64() {
        do {
            let valueB64URLBytes = try Base64URLEncoding().decode(valueB64URL) as Bytes
            XCTAssertEqual(try Base64Encoding().encode(valueB64URLBytes), valueB64)
        } catch {
            XCTFail("\(error)")
        }
    }

    func testBase64DecodeIgnoresErrorForInvalidString() throws {
        _ = try Base64Encoding().decode("\0")
    }

    func testBase64URLEncodeThrowsErrorForInvalidString() {
        do {
            _ = try Base64URLEncoding(
                base64URLTranscoder: TestBase64URLTranscoder()
            ).encode("")
        } catch JWTError.encoding {
            // pass
        } catch {
            XCTFail("Wrong error: \(error)")
        }
    }

    func testBase64URLDecodeThrowsErrorForInvalidString() {
        do {
            _ = try Base64URLEncoding(
                base64URLTranscoder: TestBase64URLTranscoder()
            ).decode("")
        } catch JWTError.decoding {
            // pass
        } catch {
            XCTFail("Wrong error: \(error)")
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
