import Vapor
import JWTKit

extension Request {
    public var jwt: JWT {
        .init(request: self)
    }

    public struct JWT {
        let request: Request

        public func verify<Payload>(as payload: Payload.Type = Payload.self) throws -> Payload
            where Payload: JWTPayload
        {
            guard let token = self.request.headers.bearerAuthorization?.token else {
                self.request.logger.error("Request is missing JWT bearer header")
                throw Abort(.unauthorized)
            }
            return try self.verify(token, as: Payload.self)
        }

        public func verify<Payload>(_ message: String, as payload: Payload.Type = Payload.self) throws -> Payload
            where Payload: JWTPayload
        {
            try self.verify([UInt8](message.utf8), as: Payload.self)
        }

        public func verify<Message, Payload>(_ message: Message, as payload: Payload.Type = Payload.self) throws -> Payload
            where Message: DataProtocol, Payload: JWTPayload
        {
            try self.request.application.jwt.signers.verify(message, as: Payload.self)
        }

        public func sign<Payload>(_ jwt: Payload, kid: JWKIdentifier? = nil) throws -> String
            where Payload: JWTPayload
        {
            try self.request.application.jwt.signers.sign(jwt, kid: kid)
        }
    }
}
