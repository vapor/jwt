import Vapor

/// A thread-safe class for retrieving JSON Web Key Sets which honors the
/// HTTP `Cache-Control`, `Expires` and `Etag` headers.
final public class AtomicJwks {
    private let uri: URI

    // Uses a private event loop so that read of the cache date and the possible
    // subsequent network download happens atomically.  Don't want multiple requests
    // coming in at once and kicking off multiple network downloads.
    private let eventLoop: EventLoop

    internal var cacheUntil: Date?
    internal var jwks: JWKS?
    internal var etag: String?

    /// The initializer.
    /// - Parameters:
    ///   - keyUrl: The URL to the JWKS data.
    public init(keyUrl: String, app: Application) {
        self.uri = URI(string: keyUrl)
        eventLoop = app.eventLoopGroup.next()
    }

    /// Downloads the JSON Web Key Set, taking into account `Cache-Control`, `Expires` and `Etag` headers..
    /// - Parameter req: The Vapor `Request` object
    public func getKeys(on req: Request) -> EventLoopFuture<JWKS> {
        eventLoop.flatSubmit {
            if let jwks = self.jwks, let cacheUntil = self.cacheUntil, Date() < cacheUntil {
                return self.eventLoop.makeSucceededFuture(jwks)
            }

            let requested = Date()

            var headers: HTTPHeaders = [:]
            if let etag = self.etag {
                headers.add(name: .ifNoneMatch, value: etag)
            }


            return req.client.get(self.uri, headers: headers)
                .hop(to: self.eventLoop)
                .flatMap { (response: ClientResponse) in
                    let expires = response.headers.getExpirationDate(requestSentAt: requested)

                    if response.status == .notModified {
                        guard let jwks = self.jwks else {
                            return self.eventLoop.makeFailedFuture(Abort(.internalServerError))
                        }

                        self.update(expires: expires, etag: self.etag, jwks: jwks)
                    }

                    guard response.status == .ok else {
                        return self.eventLoop.makeFailedFuture(Abort(.internalServerError))
                    }

                    let decoded: JWKS

                    do {
                        decoded = try response.content.decode(JWKS.self)
                    } catch {
                        return self.eventLoop.makeFailedFuture(error)
                    }

                    self.update(expires: expires, etag: self.etag, jwks: decoded)

                    return self.eventLoop.makeSucceededFuture(decoded)
            }.hop(to: req.eventLoop)
        }
    }

    private func update(expires: Date?, etag: String?, jwks: JWKS) {
        if let expires = expires {
            self.jwks = jwks
            self.etag = etag
            self.cacheUntil = expires
        } else {
            self.jwks = nil
            self.etag = nil
            self.cacheUntil = nil
        }
    }
}

