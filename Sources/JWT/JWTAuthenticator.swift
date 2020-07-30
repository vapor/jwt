import Vapor

extension JWTPayload where Self: Authenticatable {
    public static func authenticator() -> Authenticator {
        JWTPayloadAuthenticator<Self>()
    }
}

private struct JWTPayloadAuthenticator<Payload>: JWTAuthenticator
    where Payload: JWTPayload & Authenticatable
{
    func authenticate(jwt: Payload, for request: Request) -> EventLoopFuture<Void> {
        request.auth.login(jwt)
        return request.eventLoop.makeSucceededFuture(())
    }
}

public protocol JWTAuthenticator: BearerAuthenticator {
    associatedtype Payload: JWTPayload
    func authenticate(jwt: Payload, for request: Request) -> EventLoopFuture<Void>
}

extension JWTAuthenticator {
    public func authenticate(bearer: BearerAuthorization, for request: Request) -> EventLoopFuture<Void> {
        do {
            return try self.authenticate(
                jwt: request.jwt.verify(bearer.token),
                for: request
            )
        } catch {
            return request.eventLoop.makeFailedFuture(error)
        }
    }
}
