import Core
import Foundation
import JSON

/// JSON web token (JWT)
public struct JWT {

    fileprivate static let separator = "."

    fileprivate let encoding: Encoding

    public let headers: JSON
    public let payload: JSON
    public let signature: String

    /// Creates a JWT with custom JSON headers and payload
    ///
    /// - parameter headers:  Headers object in JSON format
    /// - parameter payload:  Payload object in JSON format
    /// - parameter encoding: Encoding to use for the headers, payload, and signature when creating
    ///                       the token string
    /// - parameter signer:   Signer that creates the signature
    ///
    /// - throws: Any error thrown while encoding or signing
    ///
    /// - returns: A JWT value
    public init(headers: JSON,
                payload: JSON,
                encoding: Encoding = Base64Encoding(),
                signer: Signer) throws {
        self.headers = headers
        self.payload = payload
        self.encoding = encoding

        let encoded = try [headers, payload].map(encoding.encode)
        let message = encoded.joined(separator: JWT.separator)
        let bytes = try signer.sign(message.bytes)
        signature = try encoding.encode(bytes)
    }

    /// Creates a JWT with claims and custom headers
    ///
    /// - parameter headers:  Array of headers
    /// - parameter claims:   Array of claims
    /// - parameter encoding: Encoding to use for the headers, payload, and signature when creating
    ///                       the token string
    /// - parameter signer:   Signer that creates the signature
    ///
    /// - throws: Any error thrown while encoding or signing
    ///
    /// - returns: A JWT value
    public init(headers: [Header],
                claims: [Claim],
                encoding: Encoding = Base64Encoding(),
                signer: Signer) throws {
        try self.init(headers: JSON(headers),
                      payload: JSON(claims),
                      encoding: encoding,
                      signer: signer)
    }

    /// Creates a JWT with claims and default headers ("typ", and "alg")
    ///
    /// - parameter claims:   Array of claims
    /// - parameter encoding: Encoding to use for the headers, payload, and signature when creating
    ///                       the token string
    /// - parameter signer:   Signer that creates the signature
    ///
    /// - throws: Any error thrown while encoding or signing
    ///
    /// - returns: A JWT value
    public init(claims: [Claim],
                encoding: Encoding = Base64Encoding(),
                signer: Signer) throws {
        try self.init(headers: [TypeHeader(), AlgorithmHeader(signer: signer)],
                      claims: claims,
                      encoding: encoding,
                      signer: signer)
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
    public init(token: String,
                encoding: Encoding = Base64Encoding()) throws {
        let segments = token.components(separatedBy: JWT.separator)

        guard segments.count == 3 else {
            throw JWTError.incorrectNumberOfSegments
        }

        headers = try encoding.decode(segments[0])
        payload = try encoding.decode(segments[1])
        signature = segments[2]
        self.encoding = encoding
    }

    public func createToken() throws -> String {
        return [try createMessage().string(), signature].joined(separator: JWT.separator)
    }
}

extension JWT: ClaimsVerifiable {

    var node: Node {
        return payload.node
    }
}

extension JWT: SignatureVerifiable {

    var algorithmName: String? {
        return headers.object?[AlgorithmHeader.name]?.string
    }

    func createMessage() throws -> Bytes {
        return try [headers, payload]
            .map(encoding.encode)
            .joined(separator: JWT.separator)
            .bytes
    }

    public func createSignature() throws -> Bytes {
        return try encoding.decode(signature)
    }
}
