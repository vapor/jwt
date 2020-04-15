import Vapor

extension Request.JWT {
    public var apple: Apple {
        .init(request: self.request)
    }

    public struct Apple {
        let request: Request

        public func verify(applicationIdentifier: String? = nil) -> EventLoopFuture<AppleIdentityToken> {
            guard let token = self.request.headers.bearerAuthorization?.token else {
                self.request.logger.error("Request is missing JWT bearer header.")
                return self.request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            return self.verify(token, applicationIdentifier: applicationIdentifier)
        }

        public func verify(_ message: String, applicationIdentifier: String? = nil) -> EventLoopFuture<AppleIdentityToken> {
            self.verify([UInt8](message.utf8), applicationIdentifier: applicationIdentifier)
        }

        public func verify<Message>(_ message: Message, applicationIdentifier: String? = nil) -> EventLoopFuture<AppleIdentityToken>
            where Message: DataProtocol
        {
            self.request.application.jwt.apple
                .signers(on: self.request)
                .flatMapThrowing { jwks in
                    try self.verify(message, jwks: jwks, applicationIdentifier: applicationIdentifier)
                }
        }
        
        public func verify<Message: DataProtocol>(_ message: Message, jwks: JWKS, applicationIdentifier: String? = nil) throws -> AppleIdentityToken {
            let signers = try self.request.application.jwt.apple.signers(on: jwks)
            let token = try signers.verify(message, as: AppleIdentityToken.self)
            let applicationIdentifier = applicationIdentifier ?? self.request.application.jwt.apple.applicationIdentifier
            if let applicationIdentifier = applicationIdentifier {
                try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
            }
            return token
        }
    }
}

extension Application.JWT {
    public var apple: Apple {
        .init(jwt: self)
    }

    public struct Apple {
        let jwt: Application.JWT

        public func signers(on request: Request) -> EventLoopFuture<JWKS> {
            jwks.get(on: request)
        }
        
        public func signers(on jwks: JWKS) throws -> JWTSigners {
            let signers = JWTSigners()
            try signers.use(jwks: jwks)
            return signers
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
                self.jwks = .init(uri: "https://appleid.apple.com/auth/keys")
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
