import Vapor
import JWTKit

extension Application {
    public var jwt: JWT {
        .init(application: self)
    }

    public struct JWT {
        final class Storage {
            var signers: JWTSigners
            init() {
                self.signers = .init()
            }
        }

        struct Key: StorageKey {
            typealias Value = Storage
        }

        let application: Application

        public let appleJWKS: JWKSCache
        public let googleJWKS: JWKSCache

        public var signers: JWTSigners {
            get { self.storage.signers }
            set { self.storage.signers = newValue }
        }

        var storage: Storage {
            if let existing = self.application.storage[Key.self] {
                return existing
            } else {
                let new = Storage()
                self.application.storage[Key.self] = new
                return new
            }
        }

        public init(application: Application) {
            self.application = application
            self.appleJWKS = .init(keyURL: "https://appleid.apple.com/auth/keys", client: application.client)
            self.googleJWKS = .init(keyURL: "https://www.googleapis.com/oauth2/v3/certs", client: application.client)
        }
    }
}

extension Request {
    public var jwt: JWT {
        .init(request: self)
    }

    public struct JWT {
        let request: Request

        public func verify<Payload>(as payload: Payload.Type = Payload.self) throws -> Payload
            where Payload: JWTPayload
        {
            guard let token = self.request.headers.bearerAuthorization?.token else {
                self.request.logger.error("Request is missing JWT bearer header")
                throw Abort(.unauthorized)
            }
            return try self.verify(token, as: Payload.self)
        }

        public func verify<Payload>(_ message: String, as payload: Payload.Type = Payload.self) throws -> Payload
            where Payload: JWTPayload
        {
            try self.verify([UInt8](message.utf8), as: Payload.self)
        }

        public func verify<Message, Payload>(_ message: Message, as payload: Payload.Type = Payload.self) throws -> Payload
            where Message: DataProtocol, Payload: JWTPayload
        {
            try self.request.application.jwt.signers.verify(message, as: Payload.self)
        }

        /// Verifies an identity token provided by Apple
        /// - Parameter identity: The identity token to validate.
        public func verify(apple identity: String) -> EventLoopFuture<AppleIdentityToken> {
            return self.verify(identity: identity, cache: self.request.application.jwt.appleJWKS)
        }

        /// Verifies an identity token provided by Google
        /// - Parameters:
        ///   - identity: The identity token to validate.
        ///   - gSuiteDomainName: Your G Suite domain name.
        public func verify(google identity: String, gSuiteDomainName: String? = nil) -> EventLoopFuture<GoogleIdentityToken> {
            return self.verify(identity: identity, cache: self.request.application.jwt.googleJWKS)
                .flatMapThrowing { (token: GoogleIdentityToken) in
                    if let gSuiteDomainName = gSuiteDomainName {
                        guard let hd = token.hd else {
                            throw JWTError.claimVerificationFailure(name: "hd", reason: "hd claim is missing")
                        }

                        guard hd.value == gSuiteDomainName else {
                            throw JWTError.claimVerificationFailure(name: "hd", reason: "hd claim does not match gSuiteDomainName")
                        }
                    }

                    return token
            }
        }

        private func verify<T>(identity: String, cache: JWKSCache) -> EventLoopFuture<T> where T: JWTPayload {
            return cache.keys(on: self.request).flatMap { jwks in
                let signers = JWTSigners()

                do {
                    try signers.use(jwks: jwks)
                    let token = try signers.verify(identity, as: T.self)

                    return self.request.eventLoop.makeSucceededFuture(token)
                } catch {
                    return self.request.eventLoop.makeFailedFuture(error)
                }
            }
        }


        public func sign<Payload>(_ jwt: Payload, kid: JWKIdentifier? = nil) throws -> String
            where Payload: JWTPayload
        {
            try self.request.application.jwt.signers.sign(jwt, kid: kid)
        }
    }
}

extension JWTError: AbortError {
    public var status: HTTPResponseStatus {
        .unauthorized
    }
}
