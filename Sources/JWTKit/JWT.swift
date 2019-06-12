import class Foundation.JSONDecoder

/// A JSON Web Token with a generic, codable payload.
///
///     let jwt = JWT(payload: ...)
///     let data = try jwt.sign(using: ...)
///
/// Learn more at https://jwt.io.
/// Read specification (RFC 7519) https://tools.ietf.org/html/rfc7519.
public struct JWT<Payload> where Payload: JWTPayload {
    /// The headers linked to this message
    public var header: JWTHeader

    /// The JSON payload within this message
    public var payload: Payload

    /// Creates a new JSON Web Signature from predefined data
    public init(header: JWTHeader = .init(), payload: Payload) {
        self.header = header
        self.payload = payload
    }
    
    /// Parses a JWT string into a JSON Web Signature
    public init<Header, Payload>(header: Header, payload: Payload) throws
        where Header: DataProtocol, Payload: DataProtocol
    {
        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        
        self.header = try jsonDecoder.decode(JWTHeader.self, from: .init(header.copyBytes()))
        self.payload = try jsonDecoder.decode(Payload.self, from: .init(payload.copyBytes()))
    }

    /// Signs the message and returns the serialized JSON web token
    public func sign(using signers: JWTSigners) throws -> Data {
        guard let kid = self.header.kid else {
            throw JWTError(identifier: "missingKID", reason: "`kid` header property required to identify signer")
        }

        let signer = try signers.requireSigner(kid: kid)
        return try signer.sign(self)
    }

    /// Signs the message and returns the serialized JSON web token
    public func sign(using signer: JWTSigner) throws -> Data {
        return try signer.sign(self)
    }
}
