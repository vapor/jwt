#if compiler(>=5.5) && canImport(_Concurrency)
import NIOCore
import Vapor

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
extension Request.JWT.Apple {
    public func verify(applicationIdentifier: String? = nil) async throws -> AppleIdentityToken {
        guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
            self._jwt._request.logger.error("Request is missing JWT bearer header.")
            throw Abort(.unauthorized)
        }
        return try await self.verify(token, applicationIdentifier: applicationIdentifier)
    }
    
    public func verify(_ message: String, applicationIdentifier: String? = nil) async throws -> AppleIdentityToken {
        try await self.verify([UInt8](message.utf8), applicationIdentifier: applicationIdentifier)
    }
    
    public func verify<Message>(_ message: Message, applicationIdentifier: String? = nil) async throws -> AppleIdentityToken
    where Message: DataProtocol
    {
        let signers = try await self._jwt._request.application.jwt.apple.signers(on: self._jwt._request)
        let token = try signers.verify(message, as: AppleIdentityToken.self)
        if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.apple.applicationIdentifier {
            try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
        }
        return token
    }
}

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
extension Application.JWT.Apple {
    public func signers(on request: Request) async throws -> JWTSigners {
        let jwks = try await self.jwks.get(on: request).get()
        let signers = JWTSigners()
        try signers.use(jwks: jwks)
        return signers
    }
}

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
extension Request.JWT.Google {
    public func verify(
        applicationIdentifier: String? = nil,
        gSuiteDomainName: String? = nil
    ) async throws -> GoogleIdentityToken {
        guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
            self._jwt._request.logger.error("Request is missing JWT bearer header.")
            throw Abort(.unauthorized)
        }
        return try await self.verify(
            token,
            applicationIdentifier: applicationIdentifier,
            gSuiteDomainName: gSuiteDomainName
        )
    }
    
    public func verify(
        _ message: String,
        applicationIdentifier: String? = nil,
        gSuiteDomainName: String? = nil
    ) async throws -> GoogleIdentityToken {
        try await self.verify(
            [UInt8](message.utf8),
            applicationIdentifier: applicationIdentifier,
            gSuiteDomainName: gSuiteDomainName
        )
    }
    
    public func verify<Message>(
        _ message: Message,
        applicationIdentifier: String? = nil,
        gSuiteDomainName: String? = nil
    ) async throws -> GoogleIdentityToken
    where Message: DataProtocol
    {
        let signers = try await self._jwt._request.application.jwt.google.signers(on: self._jwt._request)
        let token = try signers.verify(message, as: GoogleIdentityToken.self)
        if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.google.applicationIdentifier {
            try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
        }
        
        if let gSuiteDomainName = gSuiteDomainName ?? self._jwt._request.application.jwt.google.gSuiteDomainName {
            guard let hd = token.hostedDomain, hd.value == gSuiteDomainName else {
                throw JWTError.claimVerificationFailure(
                    name: "hostedDomain",
                    reason: "Hosted domain claim does not match gSuite domain name"
                )
            }
        }
        return token
    }
}

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
extension Application.JWT.Google {
    public func signers(on request: Request) async throws -> JWTSigners {
        let jwks = try await self.jwks.get(on: request).get()
        let signers = JWTSigners()
        try signers.use(jwks: jwks)
        return signers
    }
}

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
extension Request.JWT.Microsoft {
    public func verify(applicationIdentifier: String? = nil) async throws ->  MicrosoftIdentityToken {
        guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
            self._jwt._request.logger.error("Request is missing JWT bearer header.")
            throw Abort(.unauthorized)
        }
        return try await self.verify(token, applicationIdentifier: applicationIdentifier)
    }

    public func verify(_ message: String, applicationIdentifier: String? = nil) async throws -> MicrosoftIdentityToken {
        try await self.verify([UInt8](message.utf8), applicationIdentifier: applicationIdentifier)
    }

    public func verify<Message>(_ message: Message, applicationIdentifier: String? = nil) async throws -> MicrosoftIdentityToken
        where Message: DataProtocol
    {
        let signers = try await self._jwt._request.application.jwt.microsoft.signers(on: self._jwt._request)
        let token = try signers.verify(message, as: MicrosoftIdentityToken.self)
        if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.microsoft.applicationIdentifier {
            try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
        }
        return token
    }
}

@available(macOS 12, iOS 15, watchOS 8, tvOS 15, *)
extension Application.JWT.Microsoft {
    public func signers(on request: Request) async throws -> JWTSigners {
        let jwks = try await self.jwks.get(on: request).get()
        let signers = JWTSigners()
        try signers.use(jwks: jwks)
        return signers
    }
}

#endif
