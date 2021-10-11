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
        let signers = try await self._jwt._request.application.jwt.apple.signers(on: self._jwt._request).get()
        let token = try signers.verify(message, as: AppleIdentityToken.self)
        if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.apple.applicationIdentifier {
            try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
        }
        return token
    }
}


#endif
