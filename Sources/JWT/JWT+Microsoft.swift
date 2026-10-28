import NIOConcurrencyHelpers
import Vapor

extension Request.JWT {
    public var microsoft: Microsoft {
        .init(_jwt: self)
    }

    public struct Microsoft: Sendable {
        public let _jwt: Request.JWT

        public func verify(
            applicationIdentifier: String? = nil,
            expectedAudiences: [String]? = nil,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> MicrosoftIdentityToken {
            guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
                self._jwt._request.logger.error("Request is missing JWT bearer header.")
                throw Abort(.unauthorized)
            }
            return try await self.verify(
                token,
                applicationIdentifier: applicationIdentifier,
                expectedAudiences: expectedAudiences,
                trustedAdditionalAudiences: trustedAdditionalAudiences)
        }

        public func verify(
            _ message: String,
            applicationIdentifier: String? = nil,
            expectedAudiences: [String]? = nil,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> MicrosoftIdentityToken {
            try await self.verify(
                [UInt8](message.utf8),
                applicationIdentifier: applicationIdentifier,
                expectedAudiences: expectedAudiences,
                trustedAdditionalAudiences: trustedAdditionalAudiences)
        }

        public func verify(
            _ message: some DataProtocol & Sendable,
            applicationIdentifier: String? = nil,
            expectedAudiences: [String]? = nil,
            trustedAdditionalAudiences: Set<String> = []
        ) async throws -> MicrosoftIdentityToken {
            guard applicationIdentifier == nil || expectedAudiences == nil else {
                throw JWTError.generic(
                    identifier: "Audience",
                    reason: "Pass either applicationIdentifier or expectedAudiences, not both")
            }
            let keys = try await self._jwt._request.application.jwt.microsoft.keys(on: self._jwt._request)
            let configuredID = applicationIdentifier ?? self._jwt._request.application.jwt.microsoft.applicationIdentifier
            if let expectedAudiences = expectedAudiences ?? configuredID.map({ [$0] }) {
                return try await keys.verify(
                    message,
                    as: MicrosoftIdentityToken.self,
                    expectedAudiences: expectedAudiences,
                    trustedAdditionalAudiences: trustedAdditionalAudiences)
            }

            guard trustedAdditionalAudiences.isEmpty else {
                throw JWTError.generic(
                    identifier: "Audience",
                    reason: "Expected audience required when trusting additional audiences")
            }
            let token = try await verifyIdentityTokenWithoutAudience(message, as: MicrosoftIdentityToken.self, using: keys)
            self._jwt._request.logger.warning(
                "Microsoft identity token verified without an audience check; set app.jwt.microsoft.applicationIdentifier or pass expectedAudiences"
            )
            return token
        }
    }
}

extension Application.JWT {
    public var microsoft: Microsoft {
        .init(_jwt: self)
    }

    public struct Microsoft {
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
