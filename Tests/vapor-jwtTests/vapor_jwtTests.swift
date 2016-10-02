@testable import vapor_jwt
import Foundation
import HMAC
import JSON
import XCTest

enum Header {
    case algorithm
    case type
}

extension Header {

    var key: String {
        switch self {
        case .algorithm:
            return "alg"
        case .type:
            return "typ"
        }
    }
}

enum JWTError: Error {
    case notBase64Encoded
}

extension JSON {
    func base64String() throws -> String {
        return try makeBytes().base64String
    }
}

func encode(_ payload: JSON, with algorithm: Algorithm) throws -> String {
    let header = JSON([Header.algorithm.key: .string(algorithm.headerValue),
                       Header.type.key: "JWT"])

    let encodedHeaderAndPayload = "\(try header.base64String()).\(try payload.base64String())"

    let verifySignature = try algorithm.encrypt(encodedHeaderAndPayload)

    return "\(encodedHeaderAndPayload).\(verifySignature)"
}

func decode(_ jwt: String) throws -> JSON {
    guard let data = Data(base64Encoded: jwt) else {
        throw JWTError.notBase64Encoded
    }

    return try JSON(bytes: try data.makeBytes())
}

enum Algorithm {
    case none
    case hs256(String)
    case hs384(String)
    case hs512(String)
//    case rs256(String)
//    case rs384(String)
//    case rs512(String)
    case es256(String)
//    case es384(String)
//    case es512(String)
}

extension Algorithm {

    func encrypt(_ string: String) throws -> String {

        guard let method = method, let key = key else {
            return ""
        }
        return try HMAC(method, string.bytes).authenticate(key: key.bytes).base64String
    }

    var key: String? {
        switch self {
        case .hs256(let key), .hs384(let key), .hs512(let key), .es256(let key):
            return key
        default:
            return nil
        }
    }

    var headerValue: String {
        switch self {
        case .none: return "none"
        case .hs256: return "HS256"
        case .hs384: return "HS384"
        case .hs512: return "HS512"
//        case .rs256: return "RS256"
//        case .rs384: return "RS384"
//        case .rs512: return "RS512"
        case .es256: return "ES256"
//        case .es384: return "ES384"
//        case .es512: return "ES512"
        }
    }

    private var method: HMAC.Method? {
        switch self {
        case .none: return nil
        case .hs256: return .sha256
        case .hs384: return .sha384
        case .hs512: return .sha512
//        case .rs256: return
//        case .rs384: return
//        case .rs512: return
        case .es256: return .ecdsa
//        case .es384: return
//        case .es512: return
        }
    }
}

extension Algorithm {
    static var all: [Algorithm] {
        return [
            .hs256(""),
            .hs384(""),
            .hs512(""),
//            .rs256(""),
//            .rs384(""),
//            .rs512(""),
            .es256(""),
//            .es384(""),
//            .es512("")

        ]
    }
}

class vapor_jwtTests: XCTestCase {

    func testEncode() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .none), "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJhIjoiYiJ9.")
    }

    func testEncodeWithHS256Encryption() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .hs256("secret")), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8=")
    }

    func testEncodeWithHS384Encryption() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .hs384("secret")), "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.TgJIRKof/BR1EVkcRXV/xt8IxffTwQKUyOZIUUWFrC6sFAGIDe1HZksCbSIhKyoD")
    }

    func testEncodeWithHS512Encryption() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .hs512("secret")), "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.NEvauwy77uvgEvKOlGLmLJJEseamUKhAAPaGaWlD5P5qLHkLiHC9eQOy4YwR+L3BjNN1lumBhg8eEHus23CflQ==")
    }

    func testEncodeWithES256Encryption() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .es256("secret")), "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.OywPM9pIIjXLXVxfBaAN2YrPh8w=")
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

    func testHeaderKeys() {
        XCTAssertEqual(
            Algorithm.all.map { $0.headerValue }, [
                "HS256",
                "HS384",
                "HS512",
//                "RS256",
//                "RS384",
//                "RS512",
                "ES256",
//                "ES384",
//                "ES512"
            ])
    }
}
