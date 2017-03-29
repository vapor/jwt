/// JSON web token (JWT)
public struct JWT {
    fileprivate static let separator: Byte = .period

    public let headers: JSON
    public let payload: JSON
    public let signature: Bytes

    /// Used to store the token that created this
    /// JWT if it was parsed
    public let rawToken: (
        header: Bytes, 
        payload: Bytes, 
        signature: Bytes
    )?

    /// Creates a JWT with custom headers and payload
    ///
    /// - parameter headers:  Headers object as Node
    /// - parameter payload:  Payload object as Node
    /// - parameter encoding: Encoding to use for the headers, payload, and signature when creating
    ///                       the token string
    /// - parameter signer:   Signer that creates the signature
    ///
    /// - throws: Any error thrown while encoding or signing
    ///
    /// - returns: A JWT value
    public init(
        headers: JSON,
        payload: JSON,
        signer: Signer
    ) throws {
        self.headers = headers
        self.payload = payload

        let encoded = try [headers, payload].map { json in
            return try json.makeBytes().base64URLEncoded
        }
        let message = encoded[0] + [JWT.separator] + encoded[1]

        signature = try signer
            .sign(message: message)

        rawToken = nil
    }

    /// Creates a JWT with claims and default headers ("typ", and "alg")
    ///
    /// - parameter additionalHeaders: Headers to add besides the defaults ones
    /// - parameter payload:  Payload object as Node
    /// - parameter encoding: Encoding to use for the headers, payload, and signature when creating
    ///                       the token string
    /// - parameter signer:   Signer that creates the signature
    ///
    /// - throws: Any error thrown while encoding or signing
    ///
    /// - returns: A JWT value
    public init(
        additionalHeaders: [Header] = [],
        payload: JSON,
        signer: Signer
    ) throws {
        let headers: [Header] = [TypeHeader(), AlgorithmHeader(signer: signer)] + additionalHeaders
        try self.init(
            headers: JSON(headers),
            payload: payload,
            signer: signer
        )
    }

    /// Decodes a token string into a JWT
    ///
    /// - parameter token:    The token string to decode
    /// - parameter encoding: Encoding used for decoding the headers, payload, and signature
    ///
    /// - throws: JWTError.incorrectNumberOfSegments when the token does not consist of 3 "."
    ///           separated segments or any error thrown while decoding
    ///
    /// - returns: A JWT value
    public init(token: String) throws {
        let segments = token.components(
            separatedBy: [JWT.separator].makeString()
        )

        guard segments.count == 3 else {
            throw JWTError.incorrectNumberOfSegments
        }

        let parsed = segments.map { string in
            return string
                .makeBytes()
                .base64URLDecoded
        }

        headers = try JSON(bytes: parsed[0])
        payload = try JSON(bytes: parsed[1])
        signature = parsed[2]

        self.rawToken = (
            segments[0].makeBytes(),
            segments[1].makeBytes(),
            segments[2].makeBytes()
        )
    }

    /// Creates a token from the provided header and payload (claims), encoded using the JWT's 
    /// encoder and signed by the signature.
    ///
    /// - throws: Any error thrown while encoding
    ///
    /// - returns: An encoded and signed token string
    public func createToken() throws -> String {
        let tokenBytes = try createMessage()
            + [JWT.separator]
            + signature.base64URLEncoded

        return tokenBytes.makeString()
    }
}

extension JWT: ClaimsVerifiable {
    public var node: Node {
        return Node(payload.wrapped)
    }
}

extension JWT: SignatureVerifiable {
    public var algorithmName: String? {
        return headers.object?[AlgorithmHeader.name]?.string
    }

    public func createMessage() throws -> Bytes {
        if let rawToken = self.rawToken {
            return rawToken.header 
                + JWT.separator.makeBytes() 
                + rawToken.payload
        }

        return try headers.makeBytes().base64URLEncoded
            + [JWT.separator]
            + payload.makeBytes().base64URLEncoded
    }

    public func createSignature() throws -> Bytes {
        return signature
    }
}
