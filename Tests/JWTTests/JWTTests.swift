import JWT
import JWTKit
import Testing
import VaporTesting

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
            await app.jwt.keys.add(hmac: "a-string-secret-at-least-256-bits-long", digestAlgorithm: .sha256)

            await app.jwt.keys.add(hmac: "another-string-secret-at-least-256-bits-long", digestAlgorithm: .sha256, kid: "a")
            await app.jwt.keys.add(hmac: "a-third-string-secret-at-least-256-bits-long", digestAlgorithm: .sha256, kid: "b")

            app.jwt.apple.applicationIdentifier = "..."
            app.get("apple") { req async throws -> HTTPStatus in
                _ = try await req.jwt.apple.verify()
                return .ok
            }

            app.jwt.google.applicationIdentifier = "..."
            app.jwt.google.gSuiteDomainName = "..."
            app.get("google") { req async throws -> HTTPStatus in
                _ = try await req.jwt.google.verify()
                return .ok
            }

            app.jwt.microsoft.applicationIdentifier = "..."
            app.get("microsoft") { req async throws -> HTTPStatus in
                _ = try await req.jwt.microsoft.verify()
                return .ok
            }

            app.jwt.firebaseAuth.applicationIdentifier = "..."
            app.get("firebase") { req async throws -> HTTPStatus in
                _ = try await req.jwt.firebaseAuth.verify()
                return .ok
            }

            // Fetch and verify JWT from incoming request.
            app.get("me") { req async throws -> HTTPStatus in
                try await req.jwt.verify(as: TestPayload.self)
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
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.023MpwVrTea_vZ7uzgZGN1dB-XK88BSC0oyLnQDbxSI"

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
            try await app.testing().test(
                .POST, "login",
                beforeRequest: { req in
                    try req.content.encode(LoginCredentials(name: "foo"))
                },
                afterResponse: { res async throws in
                    #expect(res.status == .ok)
                    expectContent(LoginResponse.self, res) { login in
                        token = login.token
                    }
                }
            )

            guard let t = token else {
                Issue.record("login failed")
                return
            }

            // test manual authentication using req.jwt.verify
            try await app.testing().test(
                .GET, "me", headers: ["authorization": "Bearer \(t)"]
            ) { res async in
                #expect(res.status == .ok)
                #expect(res.body.string == "foo")
            }

            // create a token from a different signer
            let fakeToken = try await JWTKeyCollection()
                .add(ecdsa: ES512PrivateKey()).sign(TestUser(name: "bob"))
            try await app.testing().test(
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
            try await app.testing().test(
                .POST, "login",
                beforeRequest: { req in
                    try req.content.encode(LoginCredentials(name: "foo"))
                },
                afterResponse: { res async in
                    #expect(res.status == .ok)
                    expectContent(LoginResponse.self, res) { login in
                        token = login.token
                    }
                }
            )

            guard let token else {
                Issue.record("login failed")
                return
            }

            try await app.testing().test(
                .GET, "me", headers: ["authorization": "Bearer \(token)"]
            ) { res async in
                #expect(res.status == .ok)
                expectContent(TestUser.self, res) { user in
                    #expect(user.name == "foo")
                }
            }

            // token from same signer but for a different user
            // this tests that the guard middleware catches the failure to auth before it reaches the route handler
            let wrongNameToken = try await app.jwt.keys.sign(TestUser(name: "bob"))
            try await app.testing().test(
                .GET, "me", headers: ["authorization": "Bearer \(wrongNameToken)"]
            ) { res async in
                #expect(res.status == .unauthorized)
            }

            // create a token from a different signer
            let fakeToken = try await JWTKeyCollection().add(ecdsa: ES512PrivateKey()).sign(TestUser(name: "bob"))
            try await app.testing().test(
                .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
            ) { res async in
                #expect(res.status == .unauthorized)
            }
        }
    }

    /// Tests the Apple Sign In verification flow using a mock JWKS endpoint.
    /// This tests the full pipeline: JWKS fetching, token verification, and application identifier validation.
    @Test("Test Apple Authentication with Mock JWKS")
    func testAppleWithMockJWKS() async throws {
        // JWKS JSON with RSA key taken from JWTKit Tests
        let mockJWKS = """
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "test-apple-key",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "y_FtQ_cOcx6ZgyaqU54CESfkpttXuNnEZ07nYXXo8ylIiUFpB0r0Fecgv_tIhF1LFCWBHUsqyoSRQz0_iBRnYyIsG-yF_q1K3ll5Q_2GAS9_28jBuJGKDuKIj6dgPlr33si6bjeePTl4ZO6OZFxGYyn4x035pwGwjKGFuQRKYh0AtxwHiWeRIsAJ_B2Z-VGOpcSXH-x_YUfN8Q9FuyGUzcsVLuGizbooRSMSSoD_y_8veWOnXWbMsh0KKTON_-yTmAcLn2tOzFmsYgHQXatW0f2XjrdmmWl4VfiekFKFDvGenxum9nEJrzIJOMm6qHnIiyCNA3xbMqmr7oqeIUa-fQ",
                        "e": "AQAB"
                    }
                ]
            }
            """

        let rsaPrivateKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDL8W1D9w5zHpmD
            JqpTngIRJ+Sm21e42cRnTudhdejzKUiJQWkHSvQV5yC/+0iEXUsUJYEdSyrKhJFD
            PT+IFGdjIiwb7IX+rUreWXlD/YYBL3/byMG4kYoO4oiPp2A+WvfeyLpuN549OXhk
            7o5kXEZjKfjHTfmnAbCMoYW5BEpiHQC3HAeJZ5EiwAn8HZn5UY6lxJcf7H9hR83x
            D0W7IZTNyxUu4aLNuihFIxJKgP/L/y95Y6ddZsyyHQopM43/7JOYBwufa07MWaxi
            AdBdq1bR/ZeOt2aZaXhV+J6QUoUO8Z6fG6b2cQmvMgk4ybqoeciLII0DfFsyqavu
            ip4hRr59AgMBAAECggEAUIw994XwMw922hG/W98gOd5jtHMVJnD73UGQqTGEm+VG
            PM+Ux8iWtr/ec3Svo3elW4OkhwlVET9ikAf0u64zVzf769ty4K9YzpDQEEZlUrqL
            6SZVPKxetppKDVKx9G7BT0BAQZ+947h7EIIXwxOeyTOeijkFzSwhqqlwwy4qoqzV
            FTQS20QHE62hxzwuS5HBqw8ds183qAg9NbzR0Cp4za9qTiBB6C8KEcLqeatO+q+d
            VCDsJcAMZOvW14N6BozKgbQ/WXZQ/3kNUPBndZLzzqaILFNmB1Zf2DVVJ9gU7+EK
            xOac60StIfG81NllCTBrmRVq8yitNqwmutHMlxrIkQKBgQDvp39MkEHtNunFGkI5
            R8IB5BZjtx5OdRBKkmPasmNU8U0XoQAJUKY/9piIpCtRi87tMXv8WWmlbULi66pu
            4BnMIisw78xlIWRZTSizFrkFcEoVgEnbZBtSrOg/J5PAcjLEGCQoAdmMXAekR2/m
            htv7FPijHPNUjyIFLaxwjl9izwKBgQDZ2mQeKNRHjIb5ZBzB0ZCvUy2y4+kaLrhZ
            +CWMN1flL4dd1KuZKvCEfHY9kWOjqw6XneN4yT0aPmbBft4fihiiNW0Sm8i+fSpy
            g0klw2HJl49wnwctBpRgTdMKGo9n14OGeu0xKOAy7I4j1tKrUXiRWnP9R583Ti7c
            w7YHgdHM8wKBgEV147SaPzF08A6bzMPzY2zO4hpmsdcFoQIsKdryR04QXkrR9EO+
            52C0pYM9Kf0Jq6Ed7ZS3iaJT58YDjjNyqqd648/cQP6yzfYAIiK+HERSRnay5zU6
            b5zn1qyvWOi3cLVbVedumdJPvjtEJU/ImKvOaT5FntVMYwzjLw60hTsLAoGAZJnt
            UeAY51GFovUQMpDL96q5l7qXknewuhtVe4KzHCrun+3tsDWcDBJNp/DTymjbvDg1
            KzoC9XOLkB8+A+KJrZ5uWAGImi7Cw07NIJsxNR7AJonJjolTS4Wkxy2su49SNW/e
            yKzPm7SRjwtNDb/5pWXX2kaQx8Fa8qeOD7lrYPECgYAwQ6o0vYmr+L1tOZZgMVv9
            Jusa8beVUH5hyduJjmxbYOtFTkggAozdx7rs4BgyRsmDlV48cEmcVf/7IH4gMJLb
            O+bbERwCYUChe+piANhnwfwDHzbRd8mmQus54P06X7bWu6Rmi7gbQGVN/Z6VhbIm
            D2cOo0w4bk/3yb01xz1MEw==
            -----END PRIVATE KEY-----
            """

        try await withApp { app in
            app.get("mock-apple-jwks") { _ in
                Response(
                    status: .ok,
                    headers: ["Content-Type": "application/json"],
                    body: .init(string: mockJWKS)
                )
            }

            app.get("apple-verify") { req async throws -> String in
                let token = try await req.jwt.apple.verify()
                return token.subject.value
            }

            app.get("apple-verify-custom") { req async throws -> String in
                let token = try await req.jwt.apple.verify(applicationIdentifier: "com.custom.app")
                return token.subject.value
            }

            let privateKey = try Insecure.RSA.PrivateKey(pem: rsaPrivateKeyPEM)
            let signingKeys = await JWTKeyCollection().add(
                rsa: privateKey,
                digestAlgorithm: .sha256,
                kid: "test-apple-key"
            )

            // Valid token with correct application identifier
            let validPayload = AppleIdentityToken(
                issuer: "https://appleid.apple.com",
                audience: "com.example.app",
                expires: .init(value: Date().addingTimeInterval(3600)),
                issuedAt: .init(value: Date()),
                subject: "001234.abcdef1234567890.1234",
                email: "test@privaterelay.appleid.com",
                emailVerified: true
            )
            let validToken = try await signingKeys.sign(validPayload, kid: "test-apple-key")

            try await app.server.start(address: .hostname("localhost", port: 0))

            do {
                let port = try #require(app.http.server.shared.localAddress?.port, "Failed to get port")

                app.jwt.apple.jwksEndpoint = "http://localhost:\(port)/mock-apple-jwks"
                app.jwt.apple.applicationIdentifier = "com.example.app"

                let verifyResponse = try await app.client.get(
                    "http://localhost:\(port)/apple-verify", headers: ["Authorization": "Bearer \(validToken)"])
                #expect(verifyResponse.status == .ok)
                #expect(verifyResponse.body?.string == "001234.abcdef1234567890.1234")

                // Token with wrong application identifier should fail
                let wrongAudiencePayload = AppleIdentityToken(
                    issuer: "https://appleid.apple.com",
                    audience: "com.wrong.app",
                    expires: .init(value: Date().addingTimeInterval(3600)),
                    issuedAt: .init(value: Date()),
                    subject: "001234.abcdef1234567890.1234"
                )
                let wrongAudienceToken = try await signingKeys.sign(wrongAudiencePayload, kid: "test-apple-key")

                let wrongAudienceResponse = try await app.client.get(
                    "http://localhost:\(port)/apple-verify", headers: ["Authorization": "Bearer \(wrongAudienceToken)"])
                #expect(wrongAudienceResponse.status == .unauthorized)

                // Expired token should fail
                let expiredPayload = AppleIdentityToken(
                    issuer: "https://appleid.apple.com",
                    audience: "com.example.app",
                    expires: .init(value: Date().addingTimeInterval(-3600)),
                    issuedAt: .init(value: Date().addingTimeInterval(-7200)),
                    subject: "001234.abcdef1234567890.1234"
                )
                let expiredToken = try await signingKeys.sign(expiredPayload, kid: "test-apple-key")

                let expiredTokenResponse = try await app.client.get(
                    "http://localhost:\(port)/apple-verify", headers: ["Authorization": "Bearer \(expiredToken)"])
                #expect(expiredTokenResponse.status == .unauthorized)

                // Token with wrong issuer should fail
                let wrongIssuerPayload = AppleIdentityToken(
                    issuer: "https://notapple.com",
                    audience: "com.example.app",
                    expires: .init(value: Date().addingTimeInterval(3600)),
                    issuedAt: .init(value: Date()),
                    subject: "001234.abcdef1234567890.1234"
                )
                let wrongIssuerToken = try await signingKeys.sign(wrongIssuerPayload, kid: "test-apple-key")

                let wrongIssuerResponse = try await app.client.get(
                    "http://localhost:\(port)/apple-verify", headers: ["Authorization": "Bearer \(wrongIssuerToken)"])
                #expect(wrongIssuerResponse.status == .unauthorized)

                // Missing authorization header should fail
                let missingAuthHeaderResponse = try await app.client.get("http://localhost:\(port)/apple-verify")
                #expect(missingAuthHeaderResponse.status == .unauthorized)

                // Verify application identifier can be overridden per-request
                let customAudiencePayload = AppleIdentityToken(
                    issuer: "https://appleid.apple.com",
                    audience: "com.custom.app",
                    expires: .init(value: Date().addingTimeInterval(3600)),
                    issuedAt: .init(value: Date()),
                    subject: "custom-user-id"
                )
                let customToken = try await signingKeys.sign(customAudiencePayload, kid: "test-apple-key")

                let customKidResponse = try await app.client.get(
                    "http://localhost:\(port)/apple-verify-custom", headers: ["Authorization": "Bearer \(customToken)"])
                #expect(customKidResponse.status == .ok)
                #expect(customKidResponse.body?.string == "custom-user-id")

                await app.server.shutdown()
            } catch {
                await app.server.shutdown()
                throw error
            }
        }
    }

    @Test("Test Microsoft Endpoint Switch")
    func testMicrosoftEndpointSwitch() async throws {
        try await withApp { app in
            await app.jwt.keys.add(hmac: "a-string-secret-at-least-256-bits-long", digestAlgorithm: .sha256)

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
