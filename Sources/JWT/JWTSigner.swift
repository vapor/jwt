import Crypto
import Foundation

/// A JWT signer.
public final class JWTSigner {
    /// Algorithm
    public var algorithm: JWTAlgorithm

    /// Base64 encoder
    private let base64encoder: Base64Encoder

    /// Base64 decoder
    private let base64decoder: Base64Decoder

    /// Create a new JWT signer.
    public init(algorithm: JWTAlgorithm) {
        self.algorithm = algorithm
        self.base64encoder = Base64Encoder(encoding: .base64url)
        self.base64decoder = Base64Decoder(encoding: .base64url)
    }

    /// Signs the message and returns the UTF8 of this message
    ///
    /// Can be transformed into a String like so:
    ///
    /// ```swift
    /// let signed = try jws.sign()
    /// let signedString = String(bytes: signed, encoding: .utf8)
    /// ```
    public func sign<Payload>(_ jwt: inout JWT<Payload>) throws -> Data {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.dateEncodingStrategy = .secondsSince1970
        jwt.header.alg = self.algorithm.jwtAlgorithmName
        let headerData = try jsonEncoder.encode(jwt.header)
        let encodedHeader = base64encoder.encode(data: headerData)

        let payloadData = try jsonEncoder.encode(jwt.payload)
        let encodedPayload = base64encoder.encode(data: payloadData)

        let encodedSignature = try signature(header: encodedHeader, payload: encodedPayload)
        return encodedHeader + Data([.period]) + encodedPayload + Data([.period]) + encodedSignature
    }

    /// Generates a signature for the supplied payload and header.
    public func signature(header: Data, payload: Data) throws -> Data {
        let message: Data = header + Data([.period]) + payload
        let signature = try algorithm.sign(message)
        return base64encoder.encode(data: signature)
    }

    /// Generates a signature for the supplied payload and header.
    public func verify(_ signature: Data, header: Data, payload: Data) throws -> Bool {
        let message: Data = header + Data([.period]) + payload
        let signature = try base64decoder.decode(data: signature)
        return try algorithm.verify(signature, signs: message)
    }
}

/// MARK: HMAC

extension JWTSigner {
    /// Creates an HS256 JWT signer with the supplied key
    public static func hs256(key: Data) -> JWTSigner {
        return JWTSigner(algorithm: HMACAlgorithm(.sha256, key: key))
    }

    /// Creates an HS384 JWT signer with the supplied key
    public static func hs384(key: Data) -> JWTSigner {
        return JWTSigner(algorithm: HMACAlgorithm(.sha384, key: key))
    }

    /// Creates an HS512 JWT signer with the supplied key
    public static func hs512(key: Data) -> JWTSigner {
        return JWTSigner(algorithm: HMACAlgorithm(.sha512, key: key))
    }
}

/// MARK: RSA

extension JWTSigner {
    /// Creates an RS256 JWT signer with the supplied key
    public static func rs256(key: RSAKey) -> JWTSigner {
        return JWTSigner(algorithm: RSA(hashAlgorithm: .sha256, key: key))
    }

    /// Creates an RS384 JWT signer with the supplied key
    public static func rs384(key: RSAKey) -> JWTSigner {
        return JWTSigner(algorithm: RSA(hashAlgorithm: .sha384, key: key))
    }

    /// Creates an RS512 JWT signer with the supplied key
    public static func rs512(key: RSAKey) -> JWTSigner {
        return JWTSigner(algorithm: RSA(hashAlgorithm: .sha512, key: key))
    }
}
