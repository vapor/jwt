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
            try await self.verify(self.bearerToken(), as: Payload.self)
        }

        @discardableResult
        public func verify<Payload>(_ message: String, as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTPayload {
            try await self.verify([UInt8](message.utf8), as: Payload.self)
        }

        @discardableResult
        public func verify<Payload>(_ message: some DataProtocol & Sendable, as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTPayload {
            let payload: Payload = try await self._request.application.jwt.keys.verify(message, as: Payload.self)
            if Payload.self is any JWTIdentityToken.Type {
                self._request.logger.warning(
                    "Identity token verified without an audience check; use expectedAudience or expectedAudiences")
            }
            return payload
        }

        /// The audience-free identity-token call remains available for compatibility.
        @available(*, deprecated, message: "Audience-free identity verification is insecure; use expectedAudience or expectedAudiences")
        @discardableResult
        public func verify<Payload>(as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTIdentityToken {
            try await self.verifyUncheckedIdentityToken(
                [UInt8](self.bearerToken().utf8), as: Payload.self)
        }

        @available(*, deprecated, message: "Audience-free identity verification is insecure; use expectedAudience or expectedAudiences")
        @discardableResult
        public func verify<Payload>(_ message: String, as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTIdentityToken {
            try await self.verifyUncheckedIdentityToken([UInt8](message.utf8), as: Payload.self)
        }

        @available(*, deprecated, message: "Audience-free identity verification is insecure; use expectedAudience or expectedAudiences")
        @discardableResult
        public func verify<Payload>(_ message: some DataProtocol & Sendable, as _: Payload.Type = Payload.self) async throws -> Payload
        where Payload: JWTIdentityToken {
            try await self.verifyUncheckedIdentityToken(message, as: Payload.self)
        }

        /// Verifies an identity token for one of this application's audiences.
        @discardableResult
        public func verify<Payload>(
            as _: Payload.Type = Payload.self,
            expectedAudience: String,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> Payload where Payload: JWTIdentityToken {
            try await self.verify(
                self.bearerToken(),
                as: Payload.self,
                expectedAudience: expectedAudience,
                trustedAdditionalAudiences: trustedAdditionalAudiences)
        }

        @discardableResult
        public func verify<Payload>(
            _ message: String,
            as _: Payload.Type = Payload.self,
            expectedAudience: String,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> Payload where Payload: JWTIdentityToken {
            try await self.verify(
                [UInt8](message.utf8),
                as: Payload.self,
                expectedAudience: expectedAudience,
                trustedAdditionalAudiences: trustedAdditionalAudiences)
        }

        @discardableResult
        public func verify<Payload>(
            _ message: some DataProtocol & Sendable,
            as _: Payload.Type = Payload.self,
            expectedAudience: String,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> Payload where Payload: JWTIdentityToken {
            try await self._request.application.jwt.keys.verify(
                message,
                as: Payload.self,
                expectedAudience: expectedAudience,
                trustedAdditionalAudiences: trustedAdditionalAudiences)
        }

        /// Verifies an identity token for any of the configured audiences.
        @discardableResult
        public func verify<Payload>(
            as _: Payload.Type = Payload.self,
            expectedAudiences: some Sequence<String>,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> Payload where Payload: JWTIdentityToken {
            try await self.verify(
                self.bearerToken(),
                as: Payload.self,
                expectedAudiences: Set(expectedAudiences),
                trustedAdditionalAudiences: trustedAdditionalAudiences)
        }

        @discardableResult
        public func verify<Payload>(
            _ message: String,
            as _: Payload.Type = Payload.self,
            expectedAudiences: some Sequence<String>,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> Payload where Payload: JWTIdentityToken {
            try await self.verify(
                [UInt8](message.utf8),
                as: Payload.self,
                expectedAudiences: Set(expectedAudiences),
                trustedAdditionalAudiences: trustedAdditionalAudiences)
        }

        @discardableResult
        public func verify<Payload>(
            _ message: some DataProtocol & Sendable,
            as _: Payload.Type = Payload.self,
            expectedAudiences: some Sequence<String>,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> Payload where Payload: JWTIdentityToken {
            try await self._request.application.jwt.keys.verify(
                message,
                as: Payload.self,
                expectedAudiences: Set(expectedAudiences),
                trustedAdditionalAudiences: trustedAdditionalAudiences)
        }

        public func sign<Payload>(_ jwt: Payload, kid: JWKIdentifier? = nil, header: JWTHeader = .init()) async throws -> String
        where Payload: JWTPayload {
            try await self._request.application.jwt.keys.sign(jwt, kid: kid, header: header)
        }

        private func verifyUncheckedIdentityToken<Payload: JWTIdentityToken>(
            _ message: some DataProtocol & Sendable,
            as _: Payload.Type
        ) async throws -> Payload {
            let payload = try await verifyIdentityTokenWithoutAudience(
                message, as: Payload.self, using: self._request.application.jwt.keys)
            self._request.logger.warning(
                "Identity token verified without an audience check; use expectedAudience or expectedAudiences")
            return payload
        }

        private func bearerToken() throws -> String {
            guard let token = self._request.headers.bearerAuthorization?.token else {
                self._request.logger.error("Request is missing JWT bearer header")
                throw Abort(.unauthorized)
            }
            return token
        }
    }
}
