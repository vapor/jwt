@testable import VaporJWT
import JSON
import XCTest

let testMessage = JSON(["a": .string("b")])

final class JWTTests: XCTestCase {

    func tokenUsing(_ algorithm: Algorithm) throws -> String {
        return try JWT(payload: testMessage, algorithm: algorithm).token()
    }

    func testNoEncryption() {
        let secret = ""
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJhIjoiYiJ9."

        XCTAssertEqual(try tokenUsing(.none), token)
        XCTAssertTrue(try JWT(token: token).verifySignature(key: secret))
    }

    func testHS256Encryption() {
        let secret = "secret"
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8="

        XCTAssertEqual(try tokenUsing(.hs(._256(secret))), token)
        XCTAssertTrue(try JWT(token: token).verifySignature(key: secret))
    }

    func testHS384Encryption() {
        let secret = "secret"
        let token = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.TgJIRKof/BR1EVkcRXV/xt8IxffTwQKUyOZIUUWFrC6sFAGIDe1HZksCbSIhKyoD"

        XCTAssertEqual(try tokenUsing(.hs(._384(secret))), token)
        XCTAssertTrue(try JWT(token: token).verifySignature(key: secret))
    }

    func testHS512Encryption() {
        let secret = "secret"
        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.NEvauwy77uvgEvKOlGLmLJJEseamUKhAAPaGaWlD5P5qLHkLiHC9eQOy4YwR+L3BjNN1lumBhg8eEHus23CflQ=="

        XCTAssertEqual(try tokenUsing(.hs(._512(secret))), token)
        XCTAssertTrue(try JWT(token: token).verifySignature(key: secret))
    }

    func check(algorithm: Algorithm, publicKey: String) throws -> Bool {
        let jwt = try JWT(payload: testMessage, algorithm: algorithm)
        let token = try jwt.token()

        return try JWT(token: token).verifySignature(key: publicKey)
    }

    func testES256Encryption() {
        let privateKey = "AL3BRa7llckPgUw3Si2KCy1kRUZJ/pxJ29nlr86xlm0="
        let publicKey = "BIMulrzGbr8b4Dzj/lR5/m69XXLXfFCU0hkXr9jvpsXzNovbyb0gJYkMxrrCyYqd9ofDcTSSIWxxEtL8h5KcNBY="

        XCTAssert(try check(algorithm: .es(._256(privateKey)), publicKey: publicKey))
    }

    func testES384Encryption() {
        let privateKey = "BVjgIwqB1PeIv0YP3ZeQ7CTqW+9+yJ7Y/jXPr1tfrb3ne5TQNMU2rOxYtf6M6IN9"
        let publicKey = "BAV9NUl1v488eXcDhStPTK57Dg4Cm+XCjmFGD1IXjkF+LJNG963oUkYjV1xxNQgxJka7tsXjadei25PdZatX3GS6KivPiNu1YdeSpXxr5d73sdLU/rq/OgDLUUcic77g3A=="

        XCTAssert(try check(algorithm: .es(._384(privateKey)), publicKey: publicKey))
    }

    func testES512Encryption() {
        let privateKey = "AdcqLUGC+4OlxqGRJkz6++BD9tfDtNM1NvTQh7M0stzvMMvcaNio87YUD6Gaks0eS9Krvs1Bkqo/T7k9DW8Eyoec"
        let publicKey = "BACJKkoouMqhbgZtTSyQJHECDf/V2ArN7VwuaIUIKsx/OFiF79ccrzCSZ1MrGOmQgPAez6pqjUIjhwoHr5tRH65BggEUhC7SNvRvfMeElOrZNac9uTVnfGJ1DywnL+JtD49ytuD9GjifUPHJi4RcN36RHLXyBpF0u1+RRFbKCNhnJ132Pw=="

        XCTAssert(try check(algorithm: .es(._512(privateKey)), publicKey: publicKey))
    }

    func testParseTokenWithMissingAlgorithm() {
        assert(try JWT(token: "eyJhIjoiYiJ9.eyJhIjoiYiJ9.eyJhIjoiYiJ9"),
               throws: JWTError.missingAlgorithm)
    }

    func testIncorrectNumberOfSegments() {
        assert(try JWT(token: "."),
               throws: JWTError.incorrectNumberOfSegments)
    }

    func testDefaultHeaders() {
        do {
            let jwt = try JWT(payload: JSON([:]),
                              algorithm: .none)
            XCTAssertEqual(jwt.headers, JSON(["alg": "none", "typ": "JWT"]))
        } catch {
            XCTFail()
        }
    }
    
    func testCustomHeaders() {

        struct TestHeader: Header {
            static let headerKey = "test"
            let headerValue = "header"
        }

        do {
            let jwt = try JWT(payload: JSON([:]),
                              headers: [TestHeader()],
                              algorithm: .none)
            XCTAssertEqual(jwt.headers, JSON(["test": "header"]))
        } catch {
            XCTFail()
        }
    }

    func testCustomJSONHeaders() {
        do {
            let jwt = try JWT(payload: JSON([:]),
                              headers: JSON(["extra": "header"]),
                              algorithm: .none)
            XCTAssertEqual(jwt.headers, JSON(["extra": "header"]))
        } catch {
            XCTFail()
        }
    }

    static var all = [
        testNoEncryption,
        testHS256Encryption,
        testHS384Encryption,
        testHS512Encryption,
        testES256Encryption,
        testES384Encryption,
        testES512Encryption,
        testParseTokenWithMissingAlgorithm,
        testIncorrectNumberOfSegments,
        testCustomHeaders,
        testCustomJSONHeaders,
    ]
}
