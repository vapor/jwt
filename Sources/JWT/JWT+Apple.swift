import Vapor

extension Request.JWT {
    public var apple: Apple {
        .init(_jwt: self)
    }

    public struct Apple {
        public let _jwt: Request.JWT

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

        public func verify(_ message: some DataProtocol, applicationIdentifier: String? = nil) async throws -> AppleIdentityToken {
            let keys = try await self._jwt._request.application.jwt.apple.keys(on: self._jwt._request)
            let token = try await keys.verify(message, as: AppleIdentityToken.self)
            if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.apple.applicationIdentifier {
                try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
            }
            return token
        }
    }
}

extension Application.JWT {
    public var apple: Apple {
        .init(_jwt: self)
    }

    public struct Apple {
        public let _jwt: Application.JWT

        public func keys(on request: Request) async throws -> JWTKeyCollection {
            try await JWTKeyCollection().add(jwks: jwks.get(on: request).get())
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
