import Vapor

extension Request.JWT {
    public var google: Google {
        .init(request: self.request)
    }

    public struct Google {
        let request: Request

        public func verify(
            applicationIdentifier: String? = nil,
            gSuiteDomainName: String? = nil
        ) -> EventLoopFuture<GoogleIdentityToken> {
            guard let token = self.request.headers.bearerAuthorization?.token else {
                self.request.logger.error("Request is missing JWT bearer header.")
                return self.request.eventLoop.makeFailedFuture(Abort(.unauthorized))
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
            self.request.application.jwt.google.signers(
                on: self.request
            ).flatMapThrowing { signers in
                let token = try signers.verify(message, as: GoogleIdentityToken.self)
                if let applicationIdentifier = applicationIdentifier ?? self.request.application.jwt.google.applicationIdentifier {
                    guard token.audience.value == applicationIdentifier else {
                        throw JWTError.claimVerificationFailure(
                            name: "audience",
                            reason: "Audience claim does not match application identifier"
                        )
                    }

                }
                if let gSuiteDomainName = gSuiteDomainName ?? self.request.application.jwt.google.gSuiteDomainName {
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
