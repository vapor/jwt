@testable import VaporJWT
import JSON
import XCTest

class VaporJWTTests: XCTestCase {

    let message = JSON(["a": .string("b")])

    func testEncodeWithoutEncryption() {
        do {
            let token = try JWT(payload: message, algorithm: .none)
            XCTAssertEqual(try token.tokenString(),
                           "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJhIjoiYiJ9.")
            XCTAssertTrue(try token.verifySignature(key: ""))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithHS256Encryption() {
        do {
            let token = try JWT(payload: message, algorithm: .hs(._256("secret")))
            XCTAssertEqual(try token.tokenString(),
                           "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8=")
            XCTAssertTrue(try token.verifySignature(key: "secret"))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithHS384Encryption() {
        do {
            let token = try JWT(payload: message, algorithm: .hs(._384("secret")))
            XCTAssertEqual(try token.tokenString(),
                           "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.TgJIRKof/BR1EVkcRXV/xt8IxffTwQKUyOZIUUWFrC6sFAGIDe1HZksCbSIhKyoD")
            XCTAssertTrue(try token.verifySignature(key: "secret"))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithHS512Encryption() {
        do {
            let token = try JWT(payload: message, algorithm: .hs(._512("secret")))
            XCTAssertEqual(try token.tokenString(),
                           "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.NEvauwy77uvgEvKOlGLmLJJEseamUKhAAPaGaWlD5P5qLHkLiHC9eQOy4YwR+L3BjNN1lumBhg8eEHus23CflQ==")
            XCTAssertTrue(try token.verifySignature(key: "secret"))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithES256Encryption() {
        let privateKey = "AL3BRa7llckPgUw3Si2KCy1kRUZJ/pxJ29nlr86xlm0="
        let publicKey = "BPtT5aOJu133UmfZNr6J0xYifrtknN0sk0VbuB/xqdQHCFpzpWmm8c9HnesXRvu21o37MkzkO6hKxGFNzO73UGc="

        do {
            let token = try JWT(payload: message, algorithm: .es(._256(privateKey)))
            XCTAssertTrue(try token.verifySignature(key: publicKey))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithES384Encryption() {
        let privateKey = "BVjgIwqB1PeIv0YP3ZeQ7CTqW+9+yJ7Y/jXPr1tfrb3ne5TQNMU2rOxYtf6M6IN9"
        let publicKey = "BAV9NUl1v488eXcDhStPTK57Dg4Cm+XCjmFGD1IXjkF+LJNG963oUkYjV1xxNQgxJka7tsXjadei25PdZatX3GS6KivPiNu1YdeSpXxr5d73sdLU/rq/OgDLUUcic77g3A=="

        do {
            let token = try JWT(payload: message, algorithm: .es(._384(privateKey)))
            XCTAssertTrue(try token.verifySignature(key: publicKey))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithES512Encryption() {
        let privateKey = "AdcqLUGC+4OlxqGRJkz6++BD9tfDtNM1NvTQh7M0stzvMMvcaNio87YUD6Gaks0eS9Krvs1Bkqo/T7k9DW8Eyoec"
        let publicKey = "BACJKkoouMqhbgZtTSyQJHECDf/V2ArN7VwuaIUIKsx/OFiF79ccrzCSZ1MrGOmQgPAez6pqjUIjhwoHr5tRH65BggEUhC7SNvRvfMeElOrZNac9uTVnfGJ1DywnL+JtD49ytuD9GjifUPHJi4RcN36RHLXyBpF0u1+RRFbKCNhnJ132Pw=="

        do {
            let token = try JWT(payload: message, algorithm: .es(._512(privateKey)))
            XCTAssertTrue(try token.verifySignature(key: publicKey))
        } catch {
            XCTFail()
        }
    }

    func testDecode() {
        XCTAssertEqual(try JSON(base64Encoded: "eyJhIjoiYiJ9"), message)
    }

    func testHeaderKeys() {
        let all: [Algorithm] = [
            .none,
            .hs(._256("")),
            .hs(._384("")),
            .hs(._512("")),
            .es(._256("")),
            .es(._384("")),
            .es(._512(""))
        ]
        XCTAssertEqual(all.map { $0.headerValue }, [
            "none",
            "HS256",
            "HS384",
            "HS512",
            "ES256",
            "ES384",
            "ES512"
            ])
    }

    func testNotBase64Encoded() {
        XCTAssertThrowsError(try JSON(base64Encoded: "0")) {
            guard let error = $0 as? JWTError, case .notBase64Encoded = error else {
                XCTFail()
                return
            }
            return
        }
    }

    func testInvalidAlgorithm() {
        XCTAssertThrowsError(try Algorithm("", key: "")) {
            guard let error = $0 as? JWTError, case .unsupportedAlgorithm = error else {
                XCTFail()
                return
            }
        }
    }

    func testCustomJWTHeaders() {
        do {
            let jwt = try JWT(payload: JSON([:]), algorithm: .none, extraHeaders: ["extra": "header"])
            XCTAssertEqual(jwt.header, JSON(["alg": "none", "typ": "JWT", "extra": "header"]))
        } catch {
            XCTFail()
        }
    }

    static var allTests = [
        testEncodeWithoutEncryption,
        testEncodeWithHS256Encryption,
        testEncodeWithHS384Encryption,
        testEncodeWithHS512Encryption,
        testEncodeWithES256Encryption,
        testEncodeWithES384Encryption,
        testEncodeWithES512Encryption,
        testDecode,
        testHeaderKeys,
        testNotBase64Encoded,
    ]
}
