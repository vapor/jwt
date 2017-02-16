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
            throw JWTError.signatureVerificationFailed
        }
    }
}

struct PeriodToCommaEncoding: Encoding {
    func decode(_ string: String) throws -> Bytes {
        return string.makeBytes().map {
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
    func testSignature() throws {
        let jwt = try JWT(
            headers: .array(["header"]),
            payload: .array(["payload"]),
            encoding: PeriodToCommaEncoding(),
            signer: TildeSigner())
        XCTAssertEqual(try jwt.createToken(),
                       "[\"header\"].[\"payload\"].~[\"header\"],[\"payload\"]~")
    }

    func testInitWithToken() throws {
        let token = "{\"alg\":\"tilde\"}.[\"payload\"].~{\"alg\":\"tilde\"},[\"payload\"]~"
        let jwt = try JWT(
            token: token,
            encoding: PeriodToCommaEncoding())
        XCTAssertEqual(jwt.algorithmName, "tilde")
        XCTAssertEqual(try jwt.createToken(), token)
        try jwt.verifySignature(using: TildeSigner())
    }

    func testIncorrectNumberOfSegments() {
        XCTAssertThrowsError(
            try JWT(token: ".")
        ) {
            guard let error = $0 as? JWTError, case .incorrectNumberOfSegments = error else {
                XCTFail("Wrong error: \($0)")
                return
            }
        }
    }

    func testDefaultHeaders() throws {
        let jwt = try JWT(
            payload: EmptyNode,
            signer: TildeSigner())
        XCTAssertEqual(jwt.headers, Node(["alg": "tilde", "typ": "JWT"]))
    }

    func testCustomHeaders() throws {
        struct TestHeader: Header {
            static let name = "test"
            let node = Node.string("header")
        }

        let jwt = try JWT(
            headers: Node(TestHeader()),
            payload: EmptyNode,
            signer: TildeSigner())
        XCTAssertEqual(jwt.headers, Node(["test": "header"]))
    }

    func testCustomJSONHeaders() throws {
        let jwt = try JWT(
            headers: Node(["extra": "header"]),
            payload: EmptyNode,
            signer: TildeSigner())
        XCTAssertEqual(jwt.headers, Node(["extra": "header"]))
    }

    func testJWTClaimsCanBeVerified() throws {
        let jwt = try JWT(
            payload: EmptyNode,
            signer: TildeSigner())
        try jwt.verifyClaims([])
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
