import JWTKit
import Vapor

extension Request {
    public var jwt: JWT {
        .init(_request: self)
    }

    public struct JWT: Sendable {
        public let _request: Request

        @discardableResult
        public func verify<Payload>(as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTPayload {
            guard let token = self._request.headers.bearerAuthorization?.token else {
                self._request.logger.error("Request is missing JWT bearer header")
                throw Abort(.unauthorized)
            }
            return try await self.verify(token, as: Payload.self)
        }

        @discardableResult
        public func verify<Payload>(_ message: String, as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTPayload {
            try await self.verify([UInt8](message.utf8), as: Payload.self)
        }

        @discardableResult
        public func verify<Payload>(_ message: some DataProtocol & Sendable, as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTPayload {
            try await self._request.application.jwt.keys.verify(message, as: Payload.self)
        }

        public func sign<Payload>(_ jwt: Payload, kid: JWKIdentifier? = nil, header: JWTHeader = .init()) async throws -> String
        where Payload: JWTPayload {
            return try await self._request.application.jwt.keys.sign(jwt, kid: kid, header: header)
        }
    }
}
