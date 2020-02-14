import Vapor

/// A thread-safe and atomic class for retrieving JSON Web Key Sets which honors the
/// HTTP `Cache-Control`, `Expires` and `Etag` headers.
public final class JWKSCache {
    public enum Error: Swift.Error {
        case missingCache
        case unexpctedResponseStatus(HTTPStatus, uri: URI)
    }
    private let uri: URI
    private let client: Client
    private let sync: Lock

    struct CachedJWKS {
        var cacheUntil: Date
        var jwks: JWKS
        var eTag: String?
    }

    private var cachedJWKS: CachedJWKS?
    private var currentRequest: EventLoopFuture<JWKS>?

    /// Creates a new `JWKSCache`.
    /// - Parameters:
    ///   - keyURL: The URL to the JWKS data.
    ///   - application: The Vapor `Application`.
    public init(keyURL: String, client: Client) {
        self.uri = URI(string: keyURL)
        self.client = client
        self.sync = .init()
    }

    /// Downloads the JSON Web Key Set, taking into account `Cache-Control`, `Expires` and `Etag` headers..
    /// - Parameters:
    ///     - req: The Vapor `Request` object.
    public func keys(on request: Request) -> EventLoopFuture<JWKS> {
        self.keys(logger: request.logger, on: request.eventLoop)
    }

    /// Downloads the JSON Web Key Set, taking into account `Cache-Control`, `Expires` and `Etag` headers..
    /// - Parameters:
    ///     - logger: For logging debug messages.
    ///     - eventLoop: Event loop to be called back on.
    public func keys(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<JWKS> {
        // Synchronize access to shared state.
        self.sync.lock()
        defer { self.sync.unlock() }

        // Check if we have cached keys that are still valid.
        if let cachedJWKS = self.cachedJWKS, Date() < cachedJWKS.cacheUntil {
            return eventLoop.makeSucceededFuture(cachedJWKS.jwks)
        }

        // Check if there is already a request happening
        // to fetch keys.
        if let keys = self.currentRequest {
            // The current key request may be happening on a
            // different event loop.
            return keys.hop(to: eventLoop)
        }

        // Create a new key request and store it.
        logger.debug("Requesting JWKS from \(self.uri).")
        let keys = self.requestKeys(logger: logger)
        self.currentRequest = keys

        // Once the key request finishes, clear the current
        // request and return the keys.
        return keys.map { keys in
            // Synchronize access to shared state.
            self.sync.lock()
            defer { self.sync.unlock() }
            self.currentRequest = nil
            return keys
        }.hop(to: eventLoop)
    }

    private func requestKeys(logger: Logger) -> EventLoopFuture<JWKS> {
        // Add cached eTag header to this request if we have it.
        var headers: HTTPHeaders = [:]
        if let eTag = self.cachedJWKS?.eTag {
            headers.add(name: .ifNoneMatch, value: eTag)
        }

        // Store the requested-at date to calculate expiration date.
        let requestSentAt = Date()

        // Send the GET request for the JWKs.
        return self.client.get(
            self.uri, headers: headers
        ).flatMapThrowing { response in
            // Synchronize access to shared state.
            self.sync.lock()
            defer { self.sync.unlock() }

            let expirationDate = response.headers.expirationDate(requestSentAt: requestSentAt)
            let eTag = response.headers.firstValue(name: .eTag)
            switch response.status {
            case .notModified:
                // The cached JWKS are still the latest version.
                logger.debug("Cached JWKS are still valid.")
                guard var cachedJWKS = self.cachedJWKS else {
                    throw Error.missingCache
                }

                // Update the JWKS cache if there is an expiration date.
                if let expirationDate = expirationDate {
                    // Update the cache metadata.
                    cachedJWKS.cacheUntil = expirationDate
                    cachedJWKS.eTag = eTag
                    self.cachedJWKS = cachedJWKS
                } else {
                    self.cachedJWKS = nil
                }
                return cachedJWKS.jwks
            case .ok:
                // New JWKS have been returned.
                logger.debug("New JWKS have been returned.")
                let jwks = try response.content.decode(JWKS.self)

                // Cache the JWKS if there is an expiration date.
                if let expirationDate = expirationDate {
                    if var cachedJWKS = self.cachedJWKS {
                        // Update the existing cache.
                        cachedJWKS.cacheUntil = expirationDate
                        cachedJWKS.eTag = eTag
                        cachedJWKS.jwks = jwks
                        self.cachedJWKS = cachedJWKS
                    } else {
                        // Create a new cache.
                        self.cachedJWKS = .init(cacheUntil: expirationDate, jwks: jwks, eTag: eTag)
                    }
                } else {
                    self.cachedJWKS = nil
                }
                return jwks
            default:
                throw Error.unexpctedResponseStatus(response.status, uri: self.uri)
            }
        }
    }
}
