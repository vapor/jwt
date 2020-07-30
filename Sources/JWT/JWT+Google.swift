import Vapor

extension Request.JWT {
    public var google: Google {
        .init(_jwt: self)
    }

    public struct Google {
        public let _jwt: Request.JWT

        public func verify(
            applicationIdentifier: String? = nil,
            gSuiteDomainName: String? = nil
        ) -> EventLoopFuture<GoogleIdentityToken> {
            guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
                self._jwt._request.logger.error("Request is missing JWT bearer header.")
                return self._jwt._request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            return self.verify(
                token,
                applicationIdentifier: applicationIdentifier,
                gSuiteDomainName: gSuiteDomainName
            )
        }

        public func verify(
            _ message: String,
            applicationIdentifier: String? = nil,
            gSuiteDomainName: String? = nil
        ) -> EventLoopFuture<GoogleIdentityToken> {
            self.verify(
                [UInt8](message.utf8),
                applicationIdentifier: applicationIdentifier,
                gSuiteDomainName: gSuiteDomainName
            )
        }

        public func verify<Message>(
            _ message: Message,
            applicationIdentifier: String? = nil,
            gSuiteDomainName: String? = nil
        ) -> EventLoopFuture<GoogleIdentityToken>
            where Message: DataProtocol
        {
            self._jwt._request.application.jwt.google.signers(
                on: self._jwt._request
            ).flatMapThrowing { signers in
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

    }
}

extension Application.JWT {
    public var google: Google {
        .init(_jwt: self)
    }

    public struct Google {
        public let _jwt: Application.JWT

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

        public var applicationIdentifier: String? {
            get {
                self.storage.applicationIdentifier
            }
            nonmutating set {
                self.storage.applicationIdentifier = newValue
            }
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
            var applicationIdentifier: String?
            var gSuiteDomainName: String?
            init() {
                self.jwks = .init(uri: "https://www.googleapis.com/oauth2/v3/certs")
                self.applicationIdentifier = nil
                self.gSuiteDomainName = nil
            }
        }

        private var storage: Storage {
            if let existing = self._jwt._application.storage[Key.self] {
                return existing
            } else {
                let lock = self._jwt._application.locks.lock(for: Key.self)
                lock.lock()
                defer { lock.unlock() }
                if let existing = self._jwt._application.storage[Key.self] {
                    return existing
                }
                let new = Storage()
                self._jwt._application.storage[Key.self] = new
                return new
            }
        }
    }
}
