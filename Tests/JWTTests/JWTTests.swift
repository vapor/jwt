import JWT
import JWTKit
import XCTVapor

class JWTTests: XCTestCase {
    func testDocs() async throws {
        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

        // Add HMAC with SHA-256 signer.
        await app.jwt.keys.addHS256(key: "secret")

        await app.jwt.keys.addHS256(key: "foo", kid: "a")
        await app.jwt.keys.addHS256(key: "bar", kid: "b")

        app.jwt.apple.applicationIdentifier = "..."
        app.get("apple") { req async throws -> HTTPStatus in
            let token = try await req.jwt.apple.verify()
            print(token) // AppleIdentityToken
            return .ok
        }

        app.jwt.google.applicationIdentifier = "..."
        app.jwt.google.gSuiteDomainName = "..."
        app.get("google") { req async throws -> HTTPStatus in
            let token = try await req.jwt.google.verify()
            print(token) // GoogleIdentityToken
            return .ok
        }

        app.jwt.microsoft.applicationIdentifier = "..."
        app.get("microsoft") { req async throws -> HTTPStatus in
            let token = try await req.jwt.microsoft.verify()
            print(token) // MicrosoftIdentityToken
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
            func verify(using _: JWTAlgorithm) async throws {
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
                "token": req.jwt.sign(payload, header: ["kid": "a"]),
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

        try app.test(.GET, "me", beforeRequest: { req in
            req.headers.bearerAuthorization = .init(token: """
            eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo
            """)
            print(req)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
        }).test(.POST, "login", beforeRequest: { req in
            print(req)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            print(res.body.string)
            try XCTAssertNotNil(res.content.decode([String: String].self)["token"])
        })
    }

    // manual authentication using req.jwt.verify
    func testManual() async throws {
        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

        // configures an es512 signer using random key
        await app.jwt.keys.addES512(key: ES512PrivateKey())

        // jwt creation using req.jwt.sign
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
        let fakeToken = try await JWTKeyCollection()
            .addES512(key: ES512PrivateKey()).sign(TestUser(name: "bob"))
        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
        ) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    // test middleware-based authentication using req.auth.require
    func testMiddleware() async throws {
        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

        // configures an es512 signer using random key
        await app.jwt.keys.addES512(key: ES512PrivateKey())

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
        let wrongNameToken = try await app.jwt.keys.sign(TestUser(name: "bob"))
        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(wrongNameToken)"]
        ) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }

        // create a token from a different signer
        let fakeToken = try await JWTKeyCollection().addES512(key: ES512PrivateKey()).sign(TestUser(name: "bob"))
        try app.testable().test(
            .GET, "me", headers: ["authorization": "Bearer \(fakeToken)"]
        ) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    /*
     If this test expires you might need to regenerate the JWT. Use https://github.com/0xTim/vapor-jwt-test-siwa and run the project on a real device
     Try signing in with Apple and it will print a new JWT to use.
     Note that it takes a day for the JWT to expire before the test passes
    */
    func testApple() async throws {
        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

        app.jwt.apple.applicationIdentifier = "dev.timc.siwa-demo.TILiOS"

        app.get("test") { req async throws in
            try await req.jwt.apple.verify().email ?? "none"
        }
      
        app.get("test2") { req async throws in
            try await req.jwt.apple.verify(applicationIdentifier: "dev.timc.siwa-demo.TILiOS").map {
                $0.email ?? "none"
            }
        }

        var headers = HTTPHeaders()
        headers.bearerAuthorization = .init(token: """
        eyJraWQiOiJmaDZCczhDIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiZGV2LnRpbWMuc2l3YS1kZW1vLlRJTGlPUyIsImV4cCI6MTcwODUxNTY3NiwiaWF0IjoxNzA4NDI5Mjc2LCJzdWIiOiIwMDE1NDIuYjA0MTAwYzUxYWNiNDhkM2E1NzA2ODRmMTdkNjM5NGQuMTYwMyIsImNfaGFzaCI6ImFxQjM1RXR1bWFtVUg0VjZBYklmaXciLCJlbWFpbCI6Ijh5c2JjaHZjMm1AcHJpdmF0ZXJlbGF5LmFwcGxlaWQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzX3ByaXZhdGVfZW1haWwiOnRydWUsImF1dGhfdGltZSI6MTcwODQyOTI3Niwibm9uY2Vfc3VwcG9ydGVkIjp0cnVlLCJyZWFsX3VzZXJfc3RhdHVzIjoyfQ.E4SmBvvsr-L1f4rbwoXIg23XJEdA6WQxLfT6Z0TaFRTNbufuUtvG41MwJvf62T3HdCsY1VXlhdVYmTNbzqCuax6CUObue2ndx6osInDzfTkzysx17eUeCaG1XCfq9mScuVgW8xh3ZPfIeQdsII-MnP8ZG7q-CAxf6soSza_BKrrw4TArvEXrjbZO7FI1U2K72JtVZ118wcuEWfv8JO-FWFOHgWzJujqxI_7ayVG-mQfZitmYXv5ws-stZMxA0RvIbuYLWAksI6-ehYEgeEQa6NzzcJNWm3oArB0ithQE59fqFDoKCwpLchBMANz3tmNpN194Rc4ppL-niIDWFE-0Ug
        """)

        try app.test(.GET, "test", headers: headers) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }.test(.GET, "test2", headers: headers) { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    // https://github.com/vapor/jwt-kit/issues/26
    func testSignFailureSegfault() async throws {
        struct UserPayload: JWTPayload {
            var id: UUID
            var userName: String

            func verify(using _: JWTAlgorithm) throws {}
        }

        // creates a new application for testing
        let app = Application(.testing)
        defer { app.shutdown() }

        let privateKeyString = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEAhAHFb1M+P7qjwVlR7Es/3GBq3yICZP1eZ/JShBuLO4stTGHR
        akqlOYGC+ayTxOomjp4aHFNxzHxdVe9keGv0UltP8HbRTJTubOlWl2w7zG8xAKOy
        2/9s+eE3obxPrf92Ffpbx3nef9hVh8PtiV9vSd8J9QoPtODujCBf+F8n/zIrLB0m
        7Tf6e5POZ8aJ93hNyjekljITNHoCwqmkD1HSgXiaoMC17CItJoRLANIMQPNVwe8d
        /2ZejydBVEWxNwbTzz6DPBX5uFXhmDmOcUfqT0L9l8iy66e6M/8g6roAYkTKs1vP
        PT+NfM8KwyDpx/aMTxaDwjwyOO39erV95GY6ywIDAQABAoIBAC9OazCwBjjUa+bY
        WZFyjhotu17nUzBZ1EEwB/4r2MOn5r3euCt9QKTREtziybnhp5uocPcBuGBtmQ04
        0yqMlWwGKSmlivAE10TUgiGVugBTQJ5YC7rnWGhcG5GsaGmUiP7rT4S22dO69TvI
        LRHzz3ALrAfSaTqK+THiUEIz56N+D3F9B8z35Epxug7+6o3OSWQ9u4fejnOqFexH
        TsWWaX1nlic4hp6rQ771cVI1plNxmJEfXCI62fNMa25phTUDEszp3ubjdJw/tkEM
        2WwNCyt+eocs54GA2HEmBVkOgsAYeAV8S7RjvWc7khkyR8AeP+2t7bfBZGlodGNx
        KMmrt0ECgYEA95u+OQwQRk1gkpn/mPLpZxgHvYqUQLbhu3Lutv+RyIohGvPstb95
        xtZDWJWbm71rUYQ1k72+K0mo+LrFVDKA4vtiUSj754A33Q3yWLWrbjCG35Ol6z9X
        XkaK/KZ1WHWoH6kM067nreacvDRKpWJD45ck/y5UJKL0gu45e4GHYnsCgYEAiHsR
        HDR6mKo4rZ1p4ZjgtE9avhC3f9fzbgZQv1vGw3HIKsa4Kd2AoaxNlojfRsEjvEVP
        4ettKc77ts/92X26uJrd9qORaTokI1t7nMtjub5Q+As/uSZTbvsjoMcdWi2VzL5w
        t2asQ6kyGJ2oMWeo74bDgRJFLon/K7hlHdhu//ECgYBjGsQVYz20Vc4cf2TtW/SN
        nfGjLK9QA6Lv+v2O41X/VUIQ3qbUy/G64xGLiD4DJNqqgudK3fwaqV3nSCIpJBmw
        P/vHDkddDlXNtYJVfUlDTkr9e8RCF1Up18RTgXCgWl9TZL9MjsoOMap0Ld3euikA
        FAPr2yg0jcCeEymQxHRitwKBgD0CRnPFQchcz1lMtLgUDt6LWpT8BAsyDa9xQ0dH
        T2KuyjvU+R491fJvg393T9fhHohas4raIsI9tGfUMjW27nD3SaGnHKldRCpKCsfc
        Y4f0e11mKeYqK8HAofyNBaH6HqyXtOtHClp0l+BJGZZ8MBhitaJM+IAFT/vLQehF
        h9kBAoGBANLA9PaqoPdS0zt2pFQ9P3nTPsbceFY4Uvz3gYcoCaY+ePPaPIhVAjqf
        M1Bzv2/nwqtOLc7yGwiaC1kxJeKQ/9Q+sbsGHs2KKZMoeS9sYwPRpH34Kkg9h4Dc
        waNSUrQp9XZJLA9SgN+N2JwuDi0bxsr0saaLdmWn3S3L6rsg5Cja
        -----END RSA PRIVATE KEY-----
        """

        try await app.jwt.keys.addRS256(key: Insecure.RSA.PrivateKey(pem: [UInt8](privateKeyString.utf8)))

        app.get { req async throws -> String in
            let authorizationPayload = UserPayload(id: UUID(), userName: "John Smith")
            let accessToken = try await req.jwt.sign(authorizationPayload)
            return accessToken
        }

        for _ in 0 ..< 1000 {
            try app.test(.GET, "/") { res in
                XCTAssertEqual(res.status, .ok)
            }
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

    func verify(using _: JWTAlgorithm) throws {
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
