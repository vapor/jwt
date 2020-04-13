import Vapor

extension Request.JWT {
    public var microsoft: Microsoft {
        .init(request: self.request)
    }

    public struct Microsoft {
        let request: Request

        public func verify(applicationIdentifier: String? = nil) -> EventLoopFuture<MicrosoftIdentityToken> {
            guard let token = self.request.headers.bearerAuthorization?.token else {
                self.request.logger.error("Request is missing JWT bearer header.")
                return self.request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            return self.verify(token, applicationIdentifier: applicationIdentifier)
        }

        public func verify(_ message: String, applicationIdentifier: String? = nil) -> EventLoopFuture<MicrosoftIdentityToken> {
            self.verify([UInt8](message.utf8), applicationIdentifier: applicationIdentifier)
        }

        public func verify<Message>(_ message: Message, applicationIdentifier: String? = nil) -> EventLoopFuture<MicrosoftIdentityToken>
            where Message: DataProtocol
        {
            self.request.application.jwt.microsoft.signers(
                on: self.request
            ).flatMapThrowing { signers in
                let token = try signers.verify(message, as: MicrosoftIdentityToken.self)
                if let applicationIdentifier = applicationIdentifier ?? self.request.application.jwt.microsoft.applicationIdentifier {
                    try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
                }
                return token
            }
        }
    }
}

extension Application.JWT {
    public var microsoft: Microsoft {
        .init(jwt: self)
    }

    public struct Microsoft {
        let jwt: Application.JWT

        public func signers(on request: Request) -> EventLoopFuture<JWTSigners> {
            self.jwks.get(on: request).flatMapThrowing {
                let signers = JWTSigners()
                try signers.use(jwks: $0, defaultAlgorithm: .rs256)
                return signers
            }
        }

        public var jwks: EndpointCache<JWKS> {
            self.storage.jwks
        }

        public var applicationIdentifier: String? {
            get {
                self.storage.applicationIdentifier
            }
            nonmutating set {
                self.storage.applicationIdentifier = newValue
            }
        }

        private struct Key: StorageKey, LockKey {
            typealias Value = Storage
        }

        private final class Storage {
            let jwks: EndpointCache<JWKS>
            var applicationIdentifier: String?
            init() {
                self.jwks = .init(uri: "https://login.microsoftonline.com/common/discovery/keys")
                self.applicationIdentifier = nil
            }
        }

        private var storage: Storage {
            if let existing = self.jwt.application.storage[Key.self] {
                return existing
            } else {
                let lock = self.jwt.application.locks.lock(for: Key.self)
                lock.lock()
                defer { lock.unlock() }
                if let existing = self.jwt.application.storage[Key.self] {
                    return existing
                }
                let new = Storage()
                self.jwt.application.storage[Key.self] = new
                return new
            }
        }
    }
}
