@testable import VaporJWT
import Core
import JSON
import XCTest

final class EncodingTests: XCTestCase {

    let valueB64 = "////++++abc="
    let valueB64URL = "____----abc"

    func testBase64ToBase64URL() {
        do {
            let valueB64Bytes = try Encoding.base64.decode(valueB64) as Bytes
            XCTAssertEqual(try Encoding.base64URL.encode(valueB64Bytes), valueB64URL)
        } catch {
            XCTFail("\(error)")
        }
    }

    func testBase64URLToBase64() {
        do {
            let valueB64URLBytes = try Encoding.base64URL.decode(valueB64URL) as Bytes
            XCTAssertEqual(try Encoding.base64.encode(valueB64URLBytes), valueB64)
        } catch {
            XCTFail("\(error)")
        }
    }

    static var all = [
        testBase64ToBase64URL,
        testBase64URLToBase64,
    ]
}
