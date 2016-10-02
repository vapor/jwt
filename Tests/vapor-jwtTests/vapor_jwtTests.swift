@testable import vapor_jwt
import XCTest
import JSON
import Foundation

enum JWTError: Error {
    case notBase64Encoded
}

func encode(_ payload: JSON) throws -> String {
    return try payload.makeBytes().base64String
}

func decode(_ jwt: String) throws -> JSON {
    guard let data = Data(base64Encoded: jwt) else {
        throw JWTError.notBase64Encoded
    }

    return try JSON(bytes: try data.makeBytes())
}

class vapor_jwtTests: XCTestCase {

    func testEncode() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")])), "eyJhIjoiYiJ9")
    }

    func testDecode() {
        XCTAssertEqual(try decode("eyJhIjoiYiJ9"), JSON(["a": .string("b")]))
    }

    func testNotBase64Encoded() {
        XCTAssertThrowsError(try decode("0")) {
            guard let error = $0 as? JWTError, case .notBase64Encoded = error else {
                XCTFail()
                return
            }
            return
        }
    }
}
