import JWT
import JWTKit
import Testing
import XCTVapor

@Suite("JWTTests")
struct JWTTests {
    @Test("Test Docs")
    func docs() async throws {
        struct TestPayload: JWTPayload {
            enum CodingKeys: String, CodingKey {
                case subject = "sub"
                case expiration = "exp"
                case isAdmin = "admin"
            }

            var subject: SubjectClaim

            var expiration: ExpirationClaim

            var isAdmin: Bool

            func verify(using _: some JWTAlgorithm) async throws {
                try self.expiration.verifyNotExpired()
            }
        }

        try await withApp { app in
            await app.jwt.keys.add(hmac: "secret", digestAlgorithm: .sha256)

            await app.jwt.keys.add(hmac: "foo", digestAlgorithm: .sha256, kid: "a")
            await app.jwt.keys.add(hmac: "bar", digestAlgorithm: .sha256, kid: "b")

            app.jwt.apple.applicationIdentifier = "..."
            app.get("apple") { req async throws -> HTTPStatus in
                let token = try await req.jwt.apple.verify()
                return .ok
            }

            app.jwt.google.applicationIdentifier = "..."
            app.jwt.google.gSuiteDomainName = "..."
            app.get("google") { req async throws -> HTTPStatus in
                let token = try await req.jwt.google.verify()
                return .ok
            }

            app.jwt.microsoft.applicationIdentifier = "..."
            app.get("microsoft") { req async throws -> HTTPStatus in
                let token = try await req.jwt.microsoft.verify()
                return .ok
            }

            // Fetch and verify JWT from incoming request.
            app.get("me") { req async throws -> HTTPStatus in
                let payload = try await req.jwt.verify(as: TestPayload.self)
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
                    Issue.record("Shouldn't get here if the guard middleware is working.")
                    throw Abort(.internalServerError)
                }
            }

            let token =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo"

            try await app.test(
                .GET, "me", headers: ["Authorization": "Bearer \(token)"]
            ) { res async in
                #expect(res.status == .ok)
            }

            try await app.test(.POST, "login") { res async throws in
                #expect(res.status == .ok)
                _ = try #require(res.content.decode([String: String].self)["token"])
            }
        }
    }

    // Manual authentication using req.jwt.verify
    @Test("Test Manual Authentication")
    func manualAuthentication() async throws {
        try await withApp { app in
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
                    #expect(res.status == .ok)
                    XCTAssertContent(LoginResponse.self, res) { login in
                        token = login.token
                    }
                }
            )

            guard let t = token else {
                Issue.record("login failed")
                return
            }

            // test manual authentication using req.jwt.verify
            try await app.testable().test(
                .GET, "me", headers: ["authorization": "Bearer \(t)"]
            ) { res async in
                #expect(res.status == .ok)
                #expect(res.body.string == "foo")
            }

            // create a token from a different signer
            let fakeToken = try await JWTKeyCollection()
                .add(ecdsa: ES512PrivateKey()).sign(TestUser(name: "bob"))
            try await app.testable().test(
                .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
            ) { res async in
                #expect(res.status == .unauthorized)
            }
        }
    }

    // Test middleware-based authentication using req.auth.require
    @Test("Test Middleware Authentication")
    func middlewareAuthentication() async throws {
        try await withApp { app in
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
                    Issue.record("Shouldn't get here if the guard middleware is working.")
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
                    #expect(res.status == .ok)
                    XCTAssertContent(LoginResponse.self, res) { login in
                        token = login.token
                    }
                }
            )

            guard let token else {
                Issue.record("login failed")
                return
            }

            try await app.testable().test(
                .GET, "me", headers: ["authorization": "Bearer \(token)"]
            ) { res async in
                #expect(res.status == .ok)
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
                #expect(res.status == .unauthorized)
            }

            // create a token from a different signer
            let fakeToken = try await JWTKeyCollection().add(ecdsa: ES512PrivateKey()).sign(TestUser(name: "bob"))
            try await app.testable().test(
                .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
            ) { res async in
                #expect(res.status == .unauthorized)
            }
        }
    }

    // If this test expires you might need to regenerate the JWT. Use https://github.com/0xTim/vapor-jwt-test-siwa and run the project on a real device
    // Try signing in with Apple and it will print a new JWT to use.
    // Note that it takes a day for the JWT to expire before the test passes
    @Test("Test Apple Authentication")
    func testApple() async throws {
        try await withApp { app in
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
                #expect(res.status == .unauthorized)
            }

            try await app.test(.GET, "test2", headers: headers) { res async in
                #expect(res.status == .unauthorized)
            }
        }
    }

    @Test("Test Microsoft Endpoint Switch")
    func testMicrosoftEndpointSwitch() async throws {
        try await withApp { app in
            await app.jwt.keys.add(hmac: "secret", digestAlgorithm: .sha256)

            let testUser = TestUser(name: "foo")
            let token = try await app.jwt.keys.sign(testUser)

            app.jwt.microsoft.applicationIdentifier = ""
            app.get("microsoft") { req async throws in
                let token = try await req.jwt.microsoft.verify()
                return token.name ?? "none"
            }

            try await app.test(.GET, "microsoft", headers: ["Authorization": "Bearer \(token)"]) { res async in
                #expect(res.status == .unauthorized)
            }

            app.jwt.microsoft.jwksEndpoint = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
            try await app.test(.GET, "microsoft", headers: ["Authorization": "Bearer \(token)"]) { res async in
                #expect(res.status == .unauthorized)
            }

            // Use a non-existent endpoint to show that endpoint switching works
            app.jwt.microsoft.jwksEndpoint = "https://login.microsoftonline.com/nonexistent/endpoint"
            try await app.test(.GET, "microsoft", headers: ["Authorization": "Bearer \(token)"]) { res async in
                #expect(res.status == .internalServerError)
            }
        }
    }
}
