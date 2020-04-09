import Vapor

public protocol JWTAuthenticator: BearerAuthenticator {
    associatedtype Payload: JWTPayload
    func authenticate(jwt: Payload, for request: Request) -> EventLoopFuture<Void>
}

extension JWTAuthenticator {
    public func authenticate(bearer: BearerAuthorization, for request: Request) -> EventLoopFuture<Void> {
        do {
            return try self.authenticate(
                jwt: request.jwt.verify([UInt8](bearer.token.utf8)),
                for: request
            )
        } catch {
            return request.eventLoop.makeFailedFuture(error)
        }
    }
}
