@testable import JWT
import Core
import Node
import XCTest

let testMessage = Node(["a": .string("b")])

/// Surrounds message with tildes (~)
struct TildeSigner: Signer {
    let name = "tilde"

    func sign(message: Bytes) throws -> Bytes {
        return [126] + message + [126]
    }

    func verify(signature: Bytes, message: Bytes) throws {
        guard try signature == sign(message: message) else {
            throw JWTError.verificationFailed
        }
    }
}

struct PeriodToCommaEncoding: Encoding {
    func decode(_ string: String) throws -> Bytes {
        return string.bytes.map {
            switch $0 {
            case 44: return 46
            default: return $0
            }
        }
    }

    func encode(_ bytes: Bytes) throws -> String {
        return try bytes.map {
            switch $0 {
            case 46: return 44
            default: return $0
            }
        }.string()
    }
}

final class JWTTests: XCTestCase {
    func testSignature() {
        do {
            let jwt = try JWT(headers: .array(["header"]),
                              payload: .array(["payload"]),
                              encoding: PeriodToCommaEncoding(),
                              signer: TildeSigner())
            XCTAssertEqual(try jwt.createToken(),
                           "[\"header\"].[\"payload\"].~[\"header\"],[\"payload\"]~")
        } catch {
            XCTFail()
        }
    }

    func testInitWithToken() {
        do {
            let token = "{\"alg\":\"tilde\"}.[\"payload\"].~{\"alg\":\"tilde\"},[\"payload\"]~"
            let jwt = try JWT(token: token,
                          encoding: PeriodToCommaEncoding())
            XCTAssertEqual(jwt.algorithmName, "tilde")
            XCTAssertEqual(try jwt.createToken(), token)
            try jwt.verifySignature(using: TildeSigner())
        } catch {
            XCTFail("\(error)")
        }
    }

    func testIncorrectNumberOfSegments() {
        do {
            _ = try JWT(token: ".")
        } catch JWTError.incorrectNumberOfSegments {
            // pass
        } catch {
            XCTFail("Wrong error: \(error)")
        }
    }

    func testDefaultHeaders() {
        do {
            let jwt = try JWT(payload: EmptyNode, signer: TildeSigner())
            XCTAssertEqual(jwt.headers, Node(["alg": "tilde", "typ": "JWT"]))
        } catch {
            XCTFail()
        }
    }

    func testCustomHeaders() {
        struct TestHeader: Header {
            static let name = "test"
            let node = Node.string("header")
        }

        do {
            let jwt = try JWT(headers: Node(TestHeader()),
                              payload: EmptyNode,
                              signer: TildeSigner())
            XCTAssertEqual(jwt.headers, Node(["test": "header"]))
        } catch {
            XCTFail()
        }
    }

    func testCustomJSONHeaders() {
        do {
            let jwt = try JWT(headers: Node(["extra": "header"]),
                              payload: EmptyNode,
                              signer: TildeSigner())
            XCTAssertEqual(jwt.headers, Node(["extra": "header"]))
        } catch {
            XCTFail()
        }
    }

    func testJWTClaimsCanBeVerified() {
        do {
            let jwt = try JWT(payload: EmptyNode, signer: TildeSigner())
            XCTAssertTrue(jwt.verifyClaims([]))
        } catch {
            XCTFail("\(error)")
        }
    }

    static let all = [
        ("testSignature", testSignature),
        ("testInitWithToken", testInitWithToken),
        ("testIncorrectNumberOfSegments", testIncorrectNumberOfSegments),
        ("testDefaultHeaders", testDefaultHeaders),
        ("testCustomHeaders", testCustomHeaders),
        ("testCustomJSONHeaders", testCustomJSONHeaders),
        ("testJWTClaimsCanBeVerified", testJWTClaimsCanBeVerified),
    ]
}
