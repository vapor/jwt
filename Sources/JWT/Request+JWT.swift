import JWTKit
import Vapor

public extension Request {
    var jwt: JWT {
        .init(_request: self)
    }

    struct JWT {
        public let _request: Request

        @discardableResult
        public func verify<Payload>(as _: Payload.Type = Payload.self) async throws -> Payload
            where Payload: JWTPayload
        {
            guard let token = self._request.headers.bearerAuthorization?.token else {
                self._request.logger.error("Request is missing JWT bearer header")
                throw Abort(.unauthorized)
            }
            return try await self.verify(token, as: Payload.self)
        }

        @discardableResult
        public func verify<Payload>(_ message: String, as _: Payload.Type = Payload.self) async throws -> Payload
            where Payload: JWTPayload
        {
            try await self.verify([UInt8](message.utf8), as: Payload.self)
        }

        @discardableResult
        public func verify<Message, Payload>(_ message: Message, as _: Payload.Type = Payload.self) async throws -> Payload
            where Message: DataProtocol, Payload: JWTPayload
        {
            try await self._request.application.jwt.keys.verify(message, as: Payload.self)
        }

        public func sign<Payload>(_ jwt: Payload, kid: JWKIdentifier? = nil) async throws -> String
            where Payload: JWTPayload
        {
            try await self._request.application.jwt.keys.sign(jwt, kid: kid)
        }
    }
}
