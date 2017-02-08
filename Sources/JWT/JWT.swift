import Core
import Foundation
import Node

/// JSON web token (JWT)
public struct JWT {
    fileprivate static let separator = "."

    fileprivate let encoding: Encoding

    public let headers: Node
    public let payload: Node
    public let signature: String

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
    public init(headers: Node,
                payload: Node,
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
    public init(additionalHeaders: [Header] = [],
                payload: Node,
                encoding: Encoding = Base64Encoding(),
                signer: Signer) throws {
        let headers: [Header] = [TypeHeader(), AlgorithmHeader(signer: signer)] + additionalHeaders
        try self.init(
            headers: Node(headers),
            payload: payload,
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

    /// Creates a token from the provided header and payload (claims), encoded using the JWT's 
    /// encoder and signed by the signature.
    ///
    /// - throws: Any error thrown while encoding
    ///
    /// - returns: An encoded and signed token string
    public func createToken() throws -> String {
        return [try createMessage().string(), signature].joined(separator: JWT.separator)
    }
}

extension JWT: ClaimsVerifiable {
    public var node: Node {
        return payload
    }
}

extension JWT: SignatureVerifiable {
    public var algorithmName: String? {
        return headers.object?[AlgorithmHeader.name]?.string
    }

    public func createMessage() throws -> Bytes {
        return try [headers, payload]
            .map(encoding.encode)
            .joined(separator: JWT.separator)
            .bytes
    }

    public func createSignature() throws -> Bytes {
        return try encoding.decode(signature)
    }
}
