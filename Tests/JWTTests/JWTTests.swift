import JWT
import JWTKit
import XCTVapor

class JWTTests: XCTestCase {
    var app: Application!

    override func setUp() async throws {
        app = try await Application.make(.testing)
        XCTAssert(isLoggingConfigured)
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
    }

    func testDocs() async throws {
        // Add HMAC with SHA-256 signer.
        await app.jwt.keys.add(hmac: "secret", digestAlgorithm: .sha256)

        await app.jwt.keys.add(hmac: "foo", digestAlgorithm: .sha256, kid: "a")
        await app.jwt.keys.add(hmac: "bar", digestAlgorithm: .sha256, kid: "b")

        app.jwt.apple.applicationIdentifier = "..."
        app.get("apple") { req async throws -> HTTPStatus in
            let token = try await req.jwt.apple.verify()
            print(token)  // AppleIdentityToken
            return .ok
        }

        app.jwt.google.applicationIdentifier = "..."
        app.jwt.google.gSuiteDomainName = "..."
        app.get("google") { req async throws -> HTTPStatus in
            let token = try await req.jwt.google.verify()
            print(token)  // GoogleIdentityToken
            return .ok
        }

        app.jwt.microsoft.applicationIdentifier = "..."
        app.get("microsoft") { req async throws -> HTTPStatus in
            let token = try await req.jwt.microsoft.verify()
            print(token)  // MicrosoftIdentityToken
            return .ok
        }

        // JWT payload structure.
        struct TestPayload: JWTPayload {
            // Maps the longer Swift property names to the
            // shortened keys used in the JWT payload.
            enum CodingKeys: String, CodingKey {
                case subject = "sub"
                case expiration = "exp"
                case isAdmin = "admin"
            }

            // The "sub" (subject) claim identifies the principal that is the
            // subject of the JWT.
            var subject: SubjectClaim

            // The "exp" (expiration time) claim identifies the expiration time on
            // or after which the JWT MUST NOT be accepted for processing.
            var expiration: ExpirationClaim

            // Custom data.
            // If true, the user is an admin.
            var isAdmin: Bool

            // Run any additional verification logic beyond
            // signature verification here.
            // Since we have an ExpirationClaim, we will
            // call its verify method.
            func verify(using _: some JWTAlgorithm) async throws {
                try self.expiration.verifyNotExpired()
            }
        }

        // Fetch and verify JWT from incoming request.
        app.get("me") { req async throws -> HTTPStatus in
            let payload = try await req.jwt.verify(as: TestPayload.self)
            print(payload)
            return .ok
        }

        // Generate and return a new JWT.
        app.post("login") { req async throws -> [String: String] in
            // Create a new instance of our JWTPayload
            let payload = TestPayload(
                subject: "vapor",
                expiration: .init(value: .distantFuture),
                isAdmin: true
            )
            // Return the signed JWT
            return try await [
                "token": req.jwt.sign(payload, kid: "a")
            ]
        }

        // middleware-based authentication
        // using req.auth.require
        let secure = app.grouped(TestUser.authenticator(), TestUser.guardMiddleware())
        secure.get("auth") { req -> TestUser in
            if let user = req.auth.get(TestUser.self) {
                return user
            } else {
                // throw something other than unauthorized to prove the guard middleware let us get here (it shouldn't)
                XCTFail("Shouldn't get here if the guard middleware is working.")
                throw Abort(.internalServerError)
            }
        }

        try await app.test(
            .GET, "me",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(
                    token: """
                        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo
                        """)
                print(req)
            },
            afterResponse: { res async in
                XCTAssertEqual(res.status, .ok)
            })

        try await app.test(
            .POST, "login",
            beforeRequest: { req in
                print(req)
            },
            afterResponse: { res async throws in
                XCTAssertEqual(res.status, .ok)
                print(res.body.string)
                try XCTAssertNotNil(res.content.decode([String: String].self)["token"])
            })
    }

    // manual authentication using req.jwt.verify
    func testManual() async throws {
        // configures an es512 signer using random key
        await app.jwt.keys.add(ecdsa: ES512PrivateKey())

        // sign a token
        app.post("login") { req async throws -> LoginResponse in
            let credentials = try req.content.decode(LoginCredentials.self)
            return try await LoginResponse(
                token: req.jwt.sign(TestUser(name: credentials.name))
            )
        }

        app.get("me") { req async throws -> String in
            try await req.jwt.verify(as: TestUser.self).name
        }

        // stores the token created during login
        var token: String?

        // test login
        try await app.testable().test(
            .POST, "login",
            beforeRequest: { req in
                try req.content.encode(LoginCredentials(name: "foo"))
            },
            afterResponse: { res async throws in
                XCTAssertEqual(res.status, .ok)
                XCTAssertContent(LoginResponse.self, res) { login in
                    token = login.token
                }
            })

        guard let t = token else {
            XCTFail("login failed")
            return
        }

        // test manual authentication using req.jwt.verify
        try await app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(t)"]
        ) { res async in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(res.body.string, "foo")
        }

        // create a token from a different signer
        let fakeToken = try await JWTKeyCollection()
            .add(ecdsa: ES512PrivateKey()).sign(TestUser(name: "bob"))
        try await app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
        ) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    // test middleware-based authentication using req.auth.require
    func testMiddleware() async throws {
        // configures an es512 signer using random key
        await app.jwt.keys.add(ecdsa: ES512PrivateKey())

        // jwt creation using req.jwt.sign
        app.post("login") { req async throws -> LoginResponse in
            let credentials = try req.content.decode(LoginCredentials.self)
            return try await LoginResponse(
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
        try await app.testable().test(
            .POST, "login",
            beforeRequest: { req in
                try req.content.encode(LoginCredentials(name: "foo"))
            },
            afterResponse: { res async in
                XCTAssertEqual(res.status, .ok)
                XCTAssertContent(LoginResponse.self, res) { login in
                    token = login.token
                }
            })

        guard let token else {
            XCTFail("login failed")
            return
        }

        try await app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(token)"]
        ) { res async in
            XCTAssertEqual(res.status, .ok)
            XCTAssertContent(TestUser.self, res) { user in
                XCTAssertEqual(user.name, "foo")
            }
        }

        // token from same signer but for a different user
        // this tests that the guard middleware catches the failure to auth before it reaches the route handler
        let wrongNameToken = try await app.jwt.keys.sign(TestUser(name: "bob"))
        try await app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(wrongNameToken)"]
        ) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }

        // create a token from a different signer
        let fakeToken = try await JWTKeyCollection().add(ecdsa: ES512PrivateKey()).sign(TestUser(name: "bob"))
        try await app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
        ) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    // If this test expires you might need to regenerate the JWT. Use https://github.com/0xTim/vapor-jwt-test-siwa and run the project on a real device
    // Try signing in with Apple and it will print a new JWT to use.
    // Note that it takes a day for the JWT to expire before the test passes
    func testApple() async throws {
        app.jwt.apple.applicationIdentifier = "dev.timc.siwa-demo.TILiOS"

        app.get("test") { req async throws in
            try await req.jwt.apple.verify().email ?? "none"
        }

        app.get("test2") { req async throws in
            try await req.jwt.apple.verify(applicationIdentifier: "dev.timc.siwa-demo.TILiOS").email ?? "none"
        }

        var headers = HTTPHeaders()
        headers.bearerAuthorization = .init(
            token: """
                eyJraWQiOiJmaDZCczhDIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiZGV2LnRpbWMuc2l3YS1kZW1vLlRJTGlPUyIsImV4cCI6MTcwODUxNTY3NiwiaWF0IjoxNzA4NDI5Mjc2LCJzdWIiOiIwMDE1NDIuYjA0MTAwYzUxYWNiNDhkM2E1NzA2ODRmMTdkNjM5NGQuMTYwMyIsImNfaGFzaCI6ImFxQjM1RXR1bWFtVUg0VjZBYklmaXciLCJlbWFpbCI6Ijh5c2JjaHZjMm1AcHJpdmF0ZXJlbGF5LmFwcGxlaWQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzX3ByaXZhdGVfZW1haWwiOnRydWUsImF1dGhfdGltZSI6MTcwODQyOTI3Niwibm9uY2Vfc3VwcG9ydGVkIjp0cnVlLCJyZWFsX3VzZXJfc3RhdHVzIjoyfQ.E4SmBvvsr-L1f4rbwoXIg23XJEdA6WQxLfT6Z0TaFRTNbufuUtvG41MwJvf62T3HdCsY1VXlhdVYmTNbzqCuax6CUObue2ndx6osInDzfTkzysx17eUeCaG1XCfq9mScuVgW8xh3ZPfIeQdsII-MnP8ZG7q-CAxf6soSza_BKrrw4TArvEXrjbZO7FI1U2K72JtVZ118wcuEWfv8JO-FWFOHgWzJujqxI_7ayVG-mQfZitmYXv5ws-stZMxA0RvIbuYLWAksI6-ehYEgeEQa6NzzcJNWm3oArB0ithQE59fqFDoKCwpLchBMANz3tmNpN194Rc4ppL-niIDWFE-0Ug
                """)

        try await app.test(.GET, "test", headers: headers) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }

        try await app.test(.GET, "test2", headers: headers) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    func testMicrosoftEndpointSwitch() async throws {
        await app.jwt.keys.add(hmac: "secret", digestAlgorithm: .sha256)

        let testUser = TestUser(name: "foo")
        let token = try await app.jwt.keys.sign(testUser)

        app.jwt.microsoft.applicationIdentifier = ""
        app.get("microsoft") { req async throws in
            let token = try await req.jwt.microsoft.verify()
            return token.name ?? "none"
        }

        try await app.test(.GET, "microsoft", headers: ["Authorization": "Bearer \(token)"]) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }

        app.jwt.microsoft.jwksEndpoint = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
        try await app.test(.GET, "microsoft", headers: ["Authorization": "Bearer \(token)"]) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }

        // Use a non-existent endpoint to show that endpoint switching works
        app.jwt.microsoft.jwksEndpoint = "https://login.microsoftonline.com/nonexistent/endpoint"
        try await app.test(.GET, "microsoft", headers: ["Authorization": "Bearer \(token)"]) { res async in
            XCTAssertEqual(res.status, .internalServerError)
        }
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

    func verify(using _: some JWTAlgorithm) throws {
        // nothing to verify
    }
}

struct UserAuthenticator: JWTAuthenticator {
    typealias Payload = TestUser

    func authenticate(jwt: TestUser, for request: Request) async throws {
        if jwt.name == "foo" {
            // Requiring this specific username makes the test for the guard middleware in testMiddleware() valid.
            request.auth.login(jwt)
        }
    }
}
