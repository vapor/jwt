import Vapor

extension Request.JWT {
    public var google: Google {
        .init(jwt: self)
    }

    public struct Google {
        let jwt: Request.JWT

        /// Verifies an identity token provided by Apple
        public func verify() -> EventLoopFuture<GoogleIdentityToken> {
            guard let token = self.jwt.request.headers.bearerAuthorization?.token else {
                self.jwt.request.logger.error("Request is missing JWT bearer header.")
                return self.jwt.request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            return self.verify(token)
        }

        /// Verifies an identity token provided by Apple
        /// - Parameter message: The identity token to validate.
        public func verify(_ message: String) -> EventLoopFuture<GoogleIdentityToken> {
            self.verify([UInt8](message.utf8))
        }

        /// Verifies an identity token provided by Google
        /// - Parameters:
        ///   - identity: The identity token to validate.
        ///   - gSuiteDomainName: Your G Suite domain name.
        public func verify<Message>(_ message: Message) -> EventLoopFuture<GoogleIdentityToken>
            where Message: DataProtocol
        {
            self.jwt.request.application.jwt.google.signers(
                on: self.jwt.request
            ).flatMapThrowing {
                let token = try $0.verify(message, as: GoogleIdentityToken.self)
                if let gSuiteDomainName = self.jwt.request.application.jwt.google.gSuiteDomainName {
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

    }
}

extension Application.JWT {
    public var google: Google {
        .init(jwt: self)
    }

    public struct Google {
        let jwt: Application.JWT

        public func signers(on request: Request) -> EventLoopFuture<JWTSigners> {
            self.jwks.get(on: request).flatMapThrowing {
                let signers = JWTSigners()
                try signers.use(jwks: $0)
                return signers
            }
        }

        public var jwks: EndpointCache<JWKS> {
            self.storage.jwks
        }

        public var gSuiteDomainName: String? {
            get {
                self.storage.gSuiteDomainName
            }
            nonmutating set {
                self.storage.gSuiteDomainName = newValue
            }
        }

        private struct Key: StorageKey, LockKey {
            typealias Value = Storage
        }

        private final class Storage {
            let jwks: EndpointCache<JWKS>
            var gSuiteDomainName: String?
            init() {
                self.jwks = .init(uri: "https://www.googleapis.com/oauth2/v3/certs")
                self.gSuiteDomainName = nil
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
