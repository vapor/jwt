import Vapor

public extension JWTPayload where Self: Authenticatable {
    static func authenticator() -> AsyncAuthenticator {
        JWTPayloadAuthenticator<Self>()
    }
}

private struct JWTPayloadAuthenticator<Payload>: JWTAuthenticator
    where Payload: JWTPayload & Authenticatable
{
    func authenticate(jwt: Payload, for request: Request) async throws {
        request.auth.login(jwt)
    }
}

public protocol JWTAuthenticator: AsyncBearerAuthenticator {
    associatedtype Payload: JWTPayload
    func authenticate(jwt: Payload, for request: Request) async throws
}

public extension JWTAuthenticator {
    func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        try await self.authenticate(jwt: request.jwt.verify(bearer.token), for: request)
    }
}
