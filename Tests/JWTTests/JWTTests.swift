import JWT
import XCTVapor

class JWTKitTests: XCTestCase {
    func testJWTioExample() throws {
        let app = Application(.testing)
        defer { app.shutdown() }

        app.use(JWTProvider.self)

        try app.jwt.signers.use(.es512(key: .generate()), kid: "default")

        app.post("login") { req -> LoginResponse in
            let credentials = try req.content.decode(LoginCredentials.self)
            return try LoginResponse(
                token: req.jwt.sign(TestPayload(name: credentials.name))
            )
        }

        let secure = app.grouped(UserAuthenticator().middleware())
        secure.get("me") { req in
            try req.requireAuthenticated(TestUser.self)
        }

        var token: String?

        try app.testable().test(
            .POST, "login", json: LoginCredentials(name: "foo")
        ) { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertContent(LoginResponse.self, res) { login in
                token = login.token
            }
        }

        guard let t = token else {
            XCTFail("login failed")
            return
        }

        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(t)"]
        ) { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertContent(TestUser.self, res) { user in
                XCTAssertEqual(user.name, "foo")
            }
        }
    }
}

struct LoginResponse: Content {
    var token: String
}

struct LoginCredentials: Content {
    let name: String
}

struct TestUser: Content, Authenticatable {
    var name: String
}

struct UserAuthenticator: JWTPayloadAuthenticator {
    typealias User = TestUser
    typealias Payload = TestPayload

    func authenticate(payload: TestPayload, for request: Request) -> EventLoopFuture<TestUser?> {
        return request.eventLoop.makeSucceededFuture(TestUser(name: payload.name))
    }
}

struct TestPayload: JWTPayload {
    let name: String

    func verify(using signer: JWTSigner) throws {
        // no verifiable claims
    }
}

let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
let corruptedToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HwP_3cYHBw7AhHale5wky6-sVA"

let publicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----
"""
