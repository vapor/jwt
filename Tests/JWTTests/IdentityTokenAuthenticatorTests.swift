import JWT
import JWTKit
import Testing
import VaporTesting

private struct AuthIdentityToken: JWTIdentityToken, Authenticatable {
    enum CodingKeys: String, CodingKey {
        case audience = "aud"
        case subject = "sub"
    }

    let audience: AudienceClaim
    let subject: SubjectClaim

    func verify(using _: some JWTAlgorithm) async throws {}
}

@Suite("Identity token authentication")
struct IdentityTokenAuthenticatorTests {
    @Test("Audience-aware authenticator rejects a token for another client")
    func audienceAwareAuthenticator() async throws {
        try await withApp { app in
            await app.jwt.keys.add(
                hmac: "a-string-secret-at-least-256-bits-long",
                digestAlgorithm: .sha256)

            let protected = app.grouped(
                AuthIdentityToken.authenticator(expectedAudiences: ["client-one", "client-two"]),
                AuthIdentityToken.guardMiddleware())
            protected.get("identity") { _ in HTTPStatus.ok }
            let singleAudience = app.grouped(
                AuthIdentityToken.authenticator(expectedAudience: "client-one"),
                AuthIdentityToken.guardMiddleware())
            singleAudience.get("identity-single") { _ in HTTPStatus.ok }

            let accepted = try await app.jwt.keys.sign(
                AuthIdentityToken(audience: "client-two", subject: "user"))
            let rejected = try await app.jwt.keys.sign(
                AuthIdentityToken(audience: "other-client", subject: "user"))
            let singleAccepted = try await app.jwt.keys.sign(
                AuthIdentityToken(audience: "client-one", subject: "user"))

            try await app.testing().test(
                .GET, "identity", headers: ["Authorization": "Bearer \(accepted)"]
            ) { response in
                #expect(response.status == .ok)
            }
            try await app.testing().test(
                .GET, "identity", headers: ["Authorization": "Bearer \(rejected)"]
            ) { response in
                #expect(response.status == .unauthorized)
            }
            try await app.testing().test(
                .GET, "identity-single", headers: ["Authorization": "Bearer \(singleAccepted)"]
            ) { response in
                #expect(response.status == .ok)
            }
            try await app.testing().test(
                .GET, "identity-single", headers: ["Authorization": "Bearer \(accepted)"]
            ) { response in
                #expect(response.status == .unauthorized)
            }
        }
    }

    @Test("Generic identity-token authenticator remains audience-free for compatibility")
    func genericAuthenticatorCompatibility() async throws {
        try await withApp { app in
            await app.jwt.keys.add(
                hmac: "a-string-secret-at-least-256-bits-long",
                digestAlgorithm: .sha256)

            func genericAuthenticator<Payload: JWTPayload & Authenticatable>(_: Payload.Type) -> AsyncAuthenticator {
                Payload.authenticator()
            }
            let compatible = app.grouped(
                genericAuthenticator(AuthIdentityToken.self),
                AuthIdentityToken.guardMiddleware())
            compatible.get("identity-compatible") { _ in HTTPStatus.ok }

            let token = try await app.jwt.keys.sign(
                AuthIdentityToken(audience: "another-client", subject: "user"))
            try await app.testing().test(
                .GET, "identity-compatible", headers: ["Authorization": "Bearer \(token)"]
            ) { response in
                #expect(response.status == .ok)
            }
        }
    }
}
