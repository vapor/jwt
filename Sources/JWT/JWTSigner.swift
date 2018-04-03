import Core
import Crypto
import Foundation

/// A JWT signer.
public final class JWTSigner {
    /// Algorithm
    public var algorithm: JWTAlgorithm

    /// Create a new JWT signer.
    public init(algorithm: JWTAlgorithm) {
        self.algorithm = algorithm
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
        let encodedHeader = headerData.base64URLEncodedData()

        let payloadData = try jsonEncoder.encode(jwt.payload)
        let encodedPayload = payloadData.base64URLEncodedData()

        let encodedSignature = try signature(header: encodedHeader, payload: encodedPayload)
        return encodedHeader + Data([.period]) + encodedPayload + Data([.period]) + encodedSignature
    }

    /// Generates a signature for the supplied payload and header.
    public func signature(header: Data, payload: Data) throws -> Data {
        let message: Data = header + Data([.period]) + payload
        let signature = try algorithm.sign(message)
        return signature.base64URLEncodedData()
    }

    /// Generates a signature for the supplied payload and header.
    public func verify(_ signature: Data, header: Data, payload: Data) throws -> Bool {
        let message: Data = header + Data([.period]) + payload
        guard let signature = Data(base64URLEncoded: signature) else {
            throw JWTError(identifier: "base64", reason: "JWT signature is not valid base64-url")
        }
        return try algorithm.verify(signature, signs: message)
    }
}

/// MARK: HMAC

extension JWTSigner {
    /// Creates an HS256 JWT signer with the supplied key
    public static func hs256(key: Data) -> JWTSigner {
        return hmac(HMAC.SHA256, name: "HS256", key: key)
    }

    /// Creates an HS384 JWT signer with the supplied key
    public static func hs384(key: Data) -> JWTSigner {
        return hmac(HMAC.SHA384, name: "HS384", key: key)
    }

    /// Creates an HS512 JWT signer with the supplied key
    public static func hs512(key: Data) -> JWTSigner {
        return hmac(HMAC.SHA512, name: "HS512", key: key)
    }

    /// Creates an HMAC-based `CustomJWTAlgorithm` and `JWTSigner`.
    private static func hmac(_ hmac: HMAC, name: String, key: Data) -> JWTSigner {
        let alg = CustomJWTAlgorithm(name: name, sign: { plaintext in
            return try hmac.authenticate(plaintext, key: key)
        }, verify: { signature, plaintext in
            return try hmac.authenticate(plaintext, key: key) == signature.convertToData()
        })
        return .init(algorithm: alg)
    }
}

/// MARK: RSA

extension JWTSigner {
    /// Creates an RS256 JWT signer with the supplied key
    public static func rs256(key: RSAKey) -> JWTSigner {
        return rsa(RSA.SHA256, name: "RS256", key: key)
    }

    /// Creates an RS384 JWT signer with the supplied key
    public static func rs384(key: RSAKey) -> JWTSigner {
        return rsa(RSA.SHA384, name: "RS384", key: key)
    }

    /// Creates an RS512 JWT signer with the supplied key
    public static func rs512(key: RSAKey) -> JWTSigner {
        return rsa(RSA.SHA512, name: "RS512", key: key)
    }

    /// Creates an RSA-based `CustomJWTAlgorithm` and `JWTSigner`.
    private static func rsa(_ rsa: RSA, name: String, key: RSAKey) -> JWTSigner {
        let alg = CustomJWTAlgorithm(name: name, sign: { plaintext in
            return try rsa.sign(plaintext, key: key)
        }, verify: { signature, plaintext in
            return try rsa.verify(signature, signs: plaintext, key: key)
        })
        return .init(algorithm: alg)
    }
}
