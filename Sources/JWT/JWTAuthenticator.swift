import Vapor

extension JWTPayload where Self: Authenticatable {
    public static func authenticator() -> AsyncAuthenticator {
        JWTPayloadAuthenticator<Self>()
    }
}

extension JWTIdentityToken where Self: Authenticatable {
    /// Authenticates an identity token only when it was issued for this audience.
    /// The signing keys must be registered in `app.jwt.keys`.
    public static func authenticator(
        expectedAudience: String,
        trustedAdditionalAudiences: Set<String> = []
    ) -> AsyncAuthenticator {
        JWTIdentityTokenAuthenticator<Self>(
            expectedAudiences: [expectedAudience],
            trustedAdditionalAudiences: trustedAdditionalAudiences)
    }

    /// Authenticates an identity token for any of the configured audiences.
    /// The signing keys must be registered in `app.jwt.keys`.
    public static func authenticator(
        expectedAudiences: some Sequence<String>,
        trustedAdditionalAudiences: Set<String> = []
    ) -> AsyncAuthenticator {
        JWTIdentityTokenAuthenticator<Self>(
            expectedAudiences: Set(expectedAudiences),
            trustedAdditionalAudiences: trustedAdditionalAudiences)
    }

    @available(
        *, deprecated,
        message:
            "Identity-token authentication without an audience check is insecure; use authenticator(expectedAudience:) or authenticator(expectedAudiences:)"
    )
    public static func authenticator() -> AsyncAuthenticator {
        JWTPayloadAuthenticator<Self>()
    }
}

private struct JWTIdentityTokenAuthenticator<Payload>: AsyncBearerAuthenticator
where Payload: JWTIdentityToken & Authenticatable {
    let expectedAudiences: Set<String>
    let trustedAdditionalAudiences: Set<String>

    func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        let token: Payload = try await request.jwt.verify(
            bearer.token,
            as: Payload.self,
            expectedAudiences: self.expectedAudiences,
            trustedAdditionalAudiences: self.trustedAdditionalAudiences)
        request.auth.login(token)
    }
}

private struct JWTPayloadAuthenticator<Payload>: JWTAuthenticator
where Payload: JWTPayload & Authenticatable {
    func authenticate(jwt: Payload, for request: Request) async throws {
        request.auth.login(jwt)
    }
}

public protocol JWTAuthenticator: AsyncBearerAuthenticator {
    associatedtype Payload: JWTPayload
    func authenticate(jwt: Payload, for request: Request) async throws
}

extension JWTAuthenticator {
    public func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        try await self.authenticate(jwt: request.jwt.verify(bearer.token), for: request)
    }
}
