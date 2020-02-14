import Vapor

/// A thread-safe and atomic class for retrieving JSON Web Key Sets which honors the
/// HTTP `Cache-Control`, `Expires` and `Etag` headers.
public final class JWKSCache {
    public enum Error: Swift.Error {
        case unexpctedResponseStatus(HTTPStatus, uri: URI)
    }

    private let uri: URI
    private let client: Client
    private let sync: Lock

    struct CachedJWKS {
        var cacheUntil: Date
        var jwks: JWKS
    }

    private var cachedETag: String?
    private var cachedJWKS: CachedJWKS?
    private var currentRequest: EventLoopFuture<JWKS>?
    private var currentHeader: HTTPHeaders.CacheControl?

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
            // If no-cache or must-revalidate was set on the header, you *always* have to validate with the server.
            if self.currentHeader == nil || (self.currentHeader?.noCache == false && self.currentHeader?.mustRevalidate == false) {
                return eventLoop.makeSucceededFuture(cachedJWKS.jwks)
            }
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

        let keys = self.requestKeys(logger: logger, on: eventLoop)
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

    private func requestKeys(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<JWKS> {
        // Add cached eTag header to this request if we have it.
        var headers: HTTPHeaders = [:]
        if let eTag = self.cachedETag {
            headers.add(name: .ifNoneMatch, value: eTag)
        }

        // Store the requested-at date to calculate expiration date.
        let requestSentAt = Date()

        // Send the GET request for the JWKs.
        return self.client.get(
            self.uri, headers: headers
        ).flatMapThrowing { response -> ClientResponse in
            if !(response.status == .notModified || response.status == .ok) {
                throw Error.unexpctedResponseStatus(response.status, uri: self.uri)
            }

            return response
        }.flatMap { response -> EventLoopFuture<JWKS> in
            // Synchronize access to shared state.
            self.sync.lock()
            defer { self.sync.unlock() }

            self.currentHeader = response.headers.cacheControl
            self.cachedETag = response.headers.firstValue(name: .eTag)

            let expirationDate = response.headers.expirationDate(requestSentAt: requestSentAt)

            switch response.status {
            case .notModified:
                // The cached JWKS are still the latest version.
                logger.debug("Cached JWKS are still valid.")

                guard var cachedJWKS = self.cachedJWKS else {
                    // This should never happen. If it somehow does, just grab a full copy.
                    self.cachedETag = nil
                    return self.requestKeys(logger: logger, on: eventLoop)
                }

                // If they give a new expiration date, use that.  Otherwise, the spec says
                // that a NotModified status code should return all the same headers that
                // a Success status could would return.
                if let expirationDate = expirationDate {
                    cachedJWKS.cacheUntil = expirationDate
                }

                return eventLoop.makeSucceededFuture(cachedJWKS.jwks)

            case .ok:
                // New JWKS have been returned.
                logger.debug("New JWKS have been returned.")

                let jwks: JWKS

                do {
                    jwks = try response.content.decode(JWKS.self)
                } catch {
                    return eventLoop.makeFailedFuture(error)
                }

                // Cache the JWKS if there is an expiration date.
                if let expirationDate = expirationDate {
                    if let header = self.currentHeader, header.noStore == true {
                        // The server *shouldn't* give an expiration with no-store, but...
                        self.cachedJWKS = nil

                        return eventLoop.makeSucceededFuture(jwks)
                    }

                    self.cachedJWKS = .init(cacheUntil: expirationDate, jwks: jwks)
                } else {
                    self.cachedJWKS = nil
                }

                return eventLoop.makeSucceededFuture(jwks)

            default:
                // This won't ever happen due to the previous flatMapThrowing block.
                return eventLoop.makeFailedFuture(Abort(.internalServerError))
            }
        }.flatMapError { error -> EventLoopFuture<JWKS> in
            guard let header = self.currentHeader, let jwks = self.cachedJWKS?.jwks else {
                return eventLoop.makeFailedFuture(error)
            }

            // Not allowed to use the cache after the expiration date has passed.
            if header.mustRevalidate {
                self.cachedJWKS = nil
                self.currentHeader = nil
                self.cachedETag = nil

                return eventLoop.makeFailedFuture(error)
            }

            return eventLoop.makeSucceededFuture(jwks)
        }
    }
}
