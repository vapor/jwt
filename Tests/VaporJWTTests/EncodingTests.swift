@testable import VaporJWT
import Core
import JSON
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

    func testBase64ToBase64URL() {
        do {
            let valueB64Bytes = try Base64().decode(valueB64) as Bytes
            XCTAssertEqual(try Base64URL().encode(valueB64Bytes), valueB64URL)
        } catch {
            XCTFail("\(error)")
        }
    }

    func testBase64URLToBase64() {
        do {
            let valueB64URLBytes = try Base64URL().decode(valueB64URL) as Bytes
            XCTAssertEqual(try Base64().encode(valueB64URLBytes), valueB64)
        } catch {
            XCTFail("\(error)")
        }
    }

    func testBase64DecodeThrowsErrorForInvalidString() {
        assert(try Base64().decode("\0"), throws: JWTError.decoding)
    }

    func testBase64URLEncodeThrowsErrorForInvalidString() {
        assert(try Base64URL(base64URLTranscoder: TestBase64URLTranscoder()).encode(""),
               throws: JWTError.encoding)
    }

    func testBase64URLDecodeThrowsErrorForInvalidString() {
        assert(try Base64URL(base64URLTranscoder: TestBase64URLTranscoder()).decode(""),
               throws: JWTError.decoding)
    }

    static var all = [
        testBase64ToBase64URL,
        testBase64URLToBase64,
        testBase64DecodeThrowsErrorForInvalidString,
    ]
}
