import Vapor
import JWTKit

extension Request {
    public var jwt: JWT {
        .init(_request: self)
    }

    public struct JWT {
        public let _request: Request
        
        @discardableResult
        public func verify<Payload>(as payload: Payload.Type = Payload.self) throws -> Payload
            where Payload: JWTPayload
        {
            guard let token = self._request.headers.bearerAuthorization?.token else {
                self._request.logger.error("Request is missing JWT bearer header")
                throw Abort(.unauthorized)
            }
            return try self.verify(token, as: Payload.self)
        }
        
        @discardableResult
        public func verify<Payload>(_ message: String, as payload: Payload.Type = Payload.self) throws -> Payload
            where Payload: JWTPayload
        {
            try self.verify([UInt8](message.utf8), as: Payload.self)
        }
        
        @discardableResult
        public func verify<Message, Payload>(_ message: Message, as payload: Payload.Type = Payload.self) throws -> Payload
            where Message: DataProtocol, Payload: JWTPayload
        {
            try self._request.application.jwt.signers.verify(message, as: Payload.self)
        }

        public func sign<Payload>(_ jwt: Payload, kid: JWKIdentifier? = nil) throws -> String
            where Payload: JWTPayload
        {
            try self._request.application.jwt.signers.sign(jwt, kid: kid)
        }
    }
}
