import JWT
import XCTVapor

class JWTKitTests: XCTestCase {
    // manual authentication using req.jwt.verify
    func testManual() throws {
        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

        // configures JWT provider
        app.use(JWT.self)

        // configures an es512 signer using random key
        try app.jwt.signers.use(.es512(key: .generate()))

        // jwt creation using req.jwt.sign
        app.post("login") { req -> LoginResponse in
            let credentials = try req.content.decode(LoginCredentials.self)
            return try LoginResponse(
                token: req.jwt.sign(TestUser(name: credentials.name))
            )
        }

        app.get("me") { req -> String in
            try req.jwt.verify(as: TestUser.self).name
        }

        // stores the token created during login
        var token: String?

        // test login
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

        // test manual authentication using req.jwt.verify
        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(t)"]
        ) { res in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(res.body.string, "foo")
        }

        // create a token from a different signer
        let fakeToken = try JWTSigner.es256(key: .generate()).sign(TestUser(name: "bob"))
        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
        ) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    // test middleware-based authentication using req.auth.require
    func testMiddleware() throws {
        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

        // configures JWT provider
        app.use(JWT.self)

        // configures an es512 signer using random key
        try app.jwt.signers.use(.es512(key: .generate()))

        // jwt creation using req.jwt.sign
        app.post("login") { req -> LoginResponse in
            let credentials = try req.content.decode(LoginCredentials.self)
            return try LoginResponse(
                token: req.jwt.sign(TestUser(name: credentials.name))
            )
        }

        // middleware-based authentication
        // using req.auth.require
        let secure = app.grouped(UserAuthenticator().middleware())
        secure.get("me") { req in
            try req.auth.require(TestUser.self)
        }

        // stores the token created during login
        var token: String?

        // test login
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

        // create a token from a different signer
        let fakeToken = try JWTSigner.es256(key: .generate()).sign(TestUser(name: "bob"))
        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
        ) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

}

struct LoginResponse: Content {
    var token: String
}

struct LoginCredentials: Content {
    let name: String
}

struct TestUser: Content, Authenticatable, JWTPayload {
    var name: String

    func verify(using signer: JWTSigner) throws {
        // nothing to verify
    }
}

struct UserAuthenticator: JWTAuthenticator {
    typealias User = TestUser
    typealias Payload = TestUser

    func authenticate(jwt: TestUser, for request: Request) -> EventLoopFuture<TestUser?> {
        return request.eventLoop.makeSucceededFuture(jwt)
    }
}
