#if compiler(>=5.5) && canImport(_Concurrency)
import NIOCore
import Vapor

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
extension JWTPayload where Self: Authenticatable {
    public static func asyncAuthenticator() -> AsyncAuthenticator {
        AsyncJWTPayloadAuthenticator<Self>()
    }
}

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
private struct AsyncJWTPayloadAuthenticator<Payload>: AsyncJWTAuthenticator
    where Payload: JWTPayload & Authenticatable
{
    func authenticate(jwt: Payload, for request: Request) async throws {
        request.auth.login(jwt)
    }
}

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
public protocol AsyncJWTAuthenticator: AsyncBearerAuthenticator {
    associatedtype Payload: JWTPayload
    func authenticate(jwt: Payload, for request: Request) async throws
}

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
extension AsyncJWTAuthenticator {
    public func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        try await self.authenticate(
            jwt: request.jwt.verify(bearer.token),
            for: request
        )
    }
}


#endif
