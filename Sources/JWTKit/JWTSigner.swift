import class Foundation.JSONEncoder

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
    ///     let signature = try jwt.sign()
    ///     guard let string = String(bytes: signed, encoding: .utf8) else {
    ///         throw ...
    ///     }
    ///     print(string)
    ///
    /// - parameters:
    ///     - jwt: JWT to sign.
    /// - returns: Signed JWT data.
    public func sign<Payload>(_ jwt: JWT<Payload>) throws -> JWTMessage {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.dateEncodingStrategy = .secondsSince1970
        
        // encode header, copying header struct to mutate alg
        var header = jwt.header
        header.alg = algorithm.jwtAlgorithmName
        let headerData = try jsonEncoder.encode(header)
        let encodedHeader = headerData.base64URLEncodedBytes()

        // encode payload
        let payloadData = try jsonEncoder.encode(jwt.payload)
        let encodedPayload = payloadData.base64URLEncodedBytes()

        // combine header and payload to create signature
        let signatureData = try self.algorithm.sign(encodedHeader + [.period] + encodedPayload)
        
        // yield complete jwt
        return JWTMessage(
            bytes: encodedHeader
                + [.period]
                + encodedPayload
                + [.period]
                + signatureData.base64URLEncodedBytes()
        )
    }

    /// Generates a signature for the supplied payload and header.
    public func verify<Payload>(_ message: JWTMessage) throws -> JWT<Payload> {
        let message = message.bytes.split(separator: .period)
        guard message.count == 3 else {
            throw JWTError(identifier: "invalidJWT", reason: "Malformed JWT")
        }

        let encodedHeader = message[0]
        let encodedPayload = message[1]
        let encodedSignature = message[2]
        guard try self.algorithm.verify(
            encodedSignature.base64URLDecodedBytes(),
            signs: encodedHeader + [.period] + encodedPayload
        ) else {
            throw JWTError(identifier: "invalidSignature", reason: "Invalid JWT signature")
        }

        let jwt = try JWT<Payload>(
            header: encodedHeader.base64URLDecodedBytes(),
            payload: encodedPayload.base64URLDecodedBytes()
        )
        try jwt.payload.verify(using: self)
        return jwt
    }
}

/// MARK: HMAC

extension JWTSigner {
    /// Creates an HS256 JWT signer with the supplied key
    public static func hs256(key: CryptoData) -> JWTSigner {
        return hmac(HMAC.SHA256, name: "HS256", key: key)
    }

    /// Creates an HS384 JWT signer with the supplied key
    public static func hs384(key: CryptoData) -> JWTSigner {
        return hmac(HMAC.SHA384, name: "HS384", key: key)
    }

    /// Creates an HS512 JWT signer with the supplied key
    public static func hs512(key: CryptoData) -> JWTSigner {
        return hmac(HMAC.SHA512, name: "HS512", key: key)
    }

    /// Creates an HMAC-based `CustomJWTAlgorithm` and `JWTSigner`.
    private static func hmac(_ hmac: HMAC, name: String, key: CryptoData) -> JWTSigner {
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
