import NIOConcurrencyHelpers
import Vapor

public extension Request.JWT {
    var microsoft: Microsoft {
        .init(_jwt: self)
    }

    struct Microsoft {
        public let _jwt: Request.JWT

        public func verify(
            applicationIdentifier: String? = nil
        ) async throws -> MicrosoftIdentityToken {
            guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
                self._jwt._request.logger.error("Request is missing JWT bearer header.")
                throw Abort(.unauthorized)
            }
            return try await self.verify(token, applicationIdentifier: applicationIdentifier)
        }

        public func verify(
            _ message: String,
            applicationIdentifier: String? = nil
        ) async throws -> MicrosoftIdentityToken {
            try await self.verify([UInt8](message.utf8), applicationIdentifier: applicationIdentifier)
        }

        public func verify(
            _ message: some DataProtocol & Sendable,
            applicationIdentifier: String? = nil
        ) async throws -> MicrosoftIdentityToken {
            let keys = try await self._jwt._request.application.jwt.microsoft.keys(on: self._jwt._request)
            let token = try await keys.verify(message, as: MicrosoftIdentityToken.self)
            if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.microsoft.applicationIdentifier {
                try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
            }
            return token
        }
    }
}

public extension Application.JWT {
    var microsoft: Microsoft {
        .init(_jwt: self)
    }

    struct Microsoft {
        public let _jwt: Application.JWT

        public func keys(on request: Request) async throws -> JWTKeyCollection {
            try await JWTKeyCollection().add(jwks: jwks.get(on: request).get())
        }

        public var jwks: EndpointCache<JWKS> {
            self.storage.jwks
        }
        
        public var jwksEndpoint: URI {
            get {
                self.storage.jwksEndpoint
            }
            nonmutating set {
                self.storage.jwksEndpoint = newValue
                self.storage.jwks = .init(uri: newValue)
            }
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

        private final class Storage: Sendable {
            private struct SendableBox: Sendable {
                var jwks: EndpointCache<JWKS>
                var jwksEndpoint: URI
                var applicationIdentifier: String? = nil
            }

            private let sendableBox: NIOLockedValueBox<SendableBox>
            
            var jwks: EndpointCache<JWKS> {
                get {
                    self.sendableBox.withLockedValue { box in
                        box.jwks
                    }
                }
                set {
                    self.sendableBox.withLockedValue { box in
                        box.jwks = newValue
                    }
                }
            }

            var applicationIdentifier: String? {
                get {
                    self.sendableBox.withLockedValue { box in
                        box.applicationIdentifier
                    }
                }
                set {
                    self.sendableBox.withLockedValue { box in
                        box.applicationIdentifier = newValue
                    }
                }
            }
            
            var jwksEndpoint: URI {
                get {
                    self.sendableBox.withLockedValue { box in
                        box.jwksEndpoint
                    }
                }
                set {
                    self.sendableBox.withLockedValue { box in
                        box.jwksEndpoint = newValue
                    }
                }
            }

            init() {
                let jwksEndpoint: URI = "https://login.microsoftonline.com/common/discovery/keys"
                let box = SendableBox(
                    jwks: .init(uri: jwksEndpoint),
                    jwksEndpoint: jwksEndpoint
                )
                self.sendableBox = .init(box)
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
