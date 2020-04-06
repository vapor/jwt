import JWT
import JWTKit
import XCTVapor

class JWTKitTests: XCTestCase {
    // manual authentication using req.jwt.verify
    func testManual() throws {
        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

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
        try app.testable().test(.POST, "login", beforeRequest: { req in
            try req.content.encode(LoginCredentials(name: "foo"))
        }) { res in
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
        let secure = app.grouped(UserAuthenticator(), TestUser.guardMiddleware())
        secure.get("me") { req -> TestUser in
            if let user = req.auth.get(TestUser.self) {
                return user
            } else {
                // throw something other than unauthorized to prove the guard middleware let us get here (it shouldn't)
                XCTFail("Shouldn't get here if the guard middleware is working.")
                throw Abort(.internalServerError)
            }
        }

        // stores the token created during login
        var token: String?

        // test login
        try app.testable().test(.POST, "login", beforeRequest: { req in
            try req.content.encode(LoginCredentials(name: "foo"))
        }) { res in
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

        // token from same signer but for a different user
        // this tests that the guard middleware catches the failure to auth before it reaches the route handler
        let wrongNameToken = try app.jwt.signers.sign(TestUser(name: "bob"))
        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(wrongNameToken)"]
        ) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }

        // create a token from a different signer
        let fakeToken = try JWTSigner.es256(key: .generate()).sign(TestUser(name: "bob"))
        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
        ) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    func testApple() throws {
        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

        app.jwt.apple.applicationIdentifier = "com.gargoylesoft.SignInWithApple"

        app.get("test") { req in
            req.jwt.apple.verify().map {
                $0.email ?? "none"
            }
        }
        app.get("test2") { req in
            req.jwt.apple.verify(applicationIdentifier: "com.gargoylesoft.SignInWithApple").map {
                $0.email ?? "none"
            }
        }

        var headers = HTTPHeaders()
        headers.bearerAuthorization = .init(token: """
        eyJraWQiOiI4NkQ4OEtmIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhcmdveWxlc29mdC5TaWduSW5XaXRoQXBwbGUiLCJleHAiOjE1ODE5ODE3NDAsImlhdCI6MTU4MTk4MTE0MCwic3ViIjoiMDAwNjg1LmUyMGY4YzE4NjQzODQyZTA5MmYyMWVmYmJiYzkyNDgzLjE4MjUiLCJjX2hhc2giOiJpY0wwZUxtR1lfMzJyVU4waWVXLVN3IiwiZW1haWwiOiJpajhocmNncXBoQHByaXZhdGVyZWxheS5hcHBsZWlkLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNTgxOTgxMTQwfQ.CkHWktKcOsMtLKsFyDHerGScWZmpx0_fdHaIizyzSS-y1sqK4qy5WrLxGI5LURZR7dpTVMmXgyfbZKtxV5GKwE4JG1AnotADQQIJL56473medcgXaYI6Bu78omt0W0inJUEa_kQRf-pO44UM0uzCGROoFdoSNdSA4qyA5rkecihkKnG1h2kzSowRnyIIlawXRiNbrnAmuQr6o4Hbuox0abIWa1ZgWmtrSsNDcnlbHTZ1gQti6oewSbGXdmS7Dl6GBDrLZP8vvbXJZP--CBMIYHvfxMDvHhXxk4G2RGAq5TDJIUdbLGCfsxz6DsFkimM89gcS4XSienqfmgfDy8JY2Q
        """)

        try app.test(.GET, "test", headers: headers) { res in
            XCTAssertEqual(res.status, .unauthorized)
            XCTAssertContains(res.body.string, "expired")
        }.test(.GET, "test2", headers: headers) { res in
            XCTAssertEqual(res.status, .unauthorized)
            XCTAssertContains(res.body.string, "expired")
        }
    }

    override func setUp() {
        XCTAssert(isLoggingConfigured)
    }
}

extension ByteBuffer {
    var string: String {
        .init(decoding: self.readableBytesView, as: UTF8.self)
    }
}

let isLoggingConfigured: Bool = {
    LoggingSystem.bootstrap { label in
        var handler = StreamLogHandler.standardOutput(label: label)
        handler.logLevel = .debug
        return handler
    }
    return true
}()


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
    typealias Payload = TestUser

    func authenticate(jwt: TestUser, for request: Request) -> EventLoopFuture<Void> {
        if jwt.name == "foo" {
            // Requiring this specific username makes the test for the guard middleware in testMiddleware() valid.
            request.auth.login(jwt)
        }
        return request.eventLoop.makeSucceededFuture(())
    }
}
