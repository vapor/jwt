import Vapor

/// A thread-safe and atomic class for retrieving JSON Web Key Sets which honors the
/// HTTP `Cache-Control`, `Expires` and `Etag` headers.
public typealias JWKSCache = EndpointCache<JWKS>
