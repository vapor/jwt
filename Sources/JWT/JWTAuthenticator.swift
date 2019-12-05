import Vapor

public protocol JWTPayloadAuthenticator: JWTAuthenticator {
    func authenticate(payload: Payload, for request: Request) -> EventLoopFuture<User?>
}

extension JWTPayloadAuthenticator {
    public func authenticate(jwt: JWT<Payload>, for request: Request) -> EventLoopFuture<User?> {
        self.authenticate(payload: jwt.payload, for: request)
    }
}

public protocol JWTAuthenticator: BearerAuthenticator {
    associatedtype Payload: JWTPayload
    func authenticate(jwt: JWT<Payload>, for request: Request) -> EventLoopFuture<User?>
}

extension JWTAuthenticator {
    public func authenticate(bearer: BearerAuthorization, for request: Request) -> EventLoopFuture<User?> {
        do {
            let jwt = try JWT<Payload>(
                from: Data(bearer.token.utf8),
                verifiedBy: request.application.jwt.signers
            )
            return self.authenticate(jwt: jwt, for: request)
        } catch {
            return request.eventLoop.makeFailedFuture(error)
        }
    }
}
