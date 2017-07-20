import JWT
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

final class JWTTests: XCTestCase {
    static let all = [
        ("testSignature", testSignature),
        ("testInitWithToken", testInitWithToken),
        ("testIncorrectNumberOfSegments", testIncorrectNumberOfSegments),
        ("testDefaultHeaders", testDefaultHeaders),
        ("testCustomHeaders", testCustomHeaders),
        ("testCustomJSONHeaders", testCustomJSONHeaders),
        ("testJWTClaimsCanBeVerified", testJWTClaimsCanBeVerified),
        ("testHS256VerificationOfWellKnownToken", testHS256VerificationOfWellKnownToken),
        ("testHeaders", testHeaders),
    ]

    func testSignature() throws {
        let jwt = try JWT(
            headers: .object(["alg": "tilde"]),
            payload: .array(["payload"]),
            signer: TildeSigner()
        )
        XCTAssertEqual(
            try jwt.createToken(),
            "eyJhbGciOiJ0aWxkZSJ9.WyJwYXlsb2FkIl0.fmV5SmhiR2NpT2lKMGFXeGtaU0o5Lld5SndZWGxzYjJGa0lsMH4"
        )
    }

    func testInitWithToken() throws {
        do {
        let token = "eyJhbGciOiJ0aWxkZSJ9.WyJwYXlsb2FkIl0.fmV5SmhiR2NpT2lKMGFXeGtaU0o5Lld5SndZWGxzYjJGa0lsMH4"
        let jwt = try JWT(token: token)
        XCTAssertEqual(jwt.algorithmName, "tilde")
        XCTAssertEqual(try jwt.createToken(), token)
        try jwt.verifySignature(using: TildeSigner())
        } catch {
            XCTFail("\(error)")
        }
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
            payload: JSON(),
            signer: TildeSigner())
        XCTAssertEqual(jwt.headers, JSON(["alg": "tilde", "typ": "JWT"]))
    }

    func testCustomHeaders() throws {
        struct TestHeader: Header {
            static let name = "test"
            let node = Node.string("header")
        }

        let jwt = try JWT(
            headers: JSON(TestHeader()),
            payload: JSON(),
            signer: TildeSigner())
        XCTAssertEqual(jwt.headers, JSON(["test": "header"]))
    }

    func testCustomJSONHeaders() throws {
        let jwt = try JWT(
            headers: JSON(["extra": "header"]),
            payload: JSON(),
            signer: TildeSigner())
        XCTAssertEqual(jwt.headers, JSON(["extra": "header"]))
    }

    func testJWTClaimsCanBeVerified() throws {
        let jwt = try JWT(
            payload: JSON(),
            signer: TildeSigner())
        try jwt.verifyClaims([])
    }

    func testHS256VerificationOfWellKnownToken() throws {
        let jwt = try JWT(
            token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE0ODkwMDE0MzIsImV4cCI6MTUyMDUzODA4NCwiYXVkIjoiIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjoidHJ1ZSJ9.wvd76NP4xKMPEL0Knu0l2mi-fZPiPW49o1nsP2aMSeo"
        )

        let signer = HS256(key: "foobar".makeBytes())
        try jwt.verifySignature(using: signer)
    }

    func testHeaders() throws {
        let expiry = Date() + 1800
        let headers: [String: JSON] = ["aaaa": "bbbb", "cccc": 1]
        let payload = JSON([
            ExpirationTimeClaim(date: expiry)
        ])
        let fail = try JWT(
            additionalHeaders: headers,
            payload: payload,
            signer: HS512(key: "secret".bytes)
        )
        let token = try fail.createToken()


        let receivedJWT = try JWT(token: token)
        try receivedJWT.verifySignature(using: HS512(key: "secret".bytes))
        try receivedJWT.verifyClaims([ExpirationTimeClaim(date: Date())])
    }

    func testHeadersPassing() throws {
        let expiry = Date() + 1800
        let payload = JSON([
            ExpirationTimeClaim(date: expiry)
        ])
        let fail = try JWT(payload: payload, signer: HS512(key: "secret".bytes))
        let token = try fail.createToken()

        let receivedJWT = try JWT(token: token)
        try receivedJWT.verifySignature(using: HS512(key: "secret".bytes))
        try receivedJWT.verifyClaims([ExpirationTimeClaim(date: Date())])
    }
}
