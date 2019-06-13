import class Foundation.JSONEncoder

/// A JWT signer.
public protocol JWTSigner {
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
    public func sign<Payload>(_ jwt: JWT<Payload>) throws -> [UInt8] {
        return []
    }

    /// Generates a signature for the supplied payload and header.
    public func verify<Message, Payload>(_ message: Message, as payload: Payload.Type) throws -> JWT<Payload>
        where Message: DataProtocol
    {
        fatalError()
    }
}

/// MARK: HMAC

//extension JWTSigner {
//    /// Creates an HS256 JWT signer with the supplied key
//    public static func hs256<Key>(key: CryptoData) -> JWTSigner {
//        return hmac(HMAC.SHA256, name: "HS256", key: key)
//    }
//
//    /// Creates an HS384 JWT signer with the supplied key
//    public static func hs384(key: CryptoData) -> JWTSigner {
//        return hmac(HMAC.SHA384, name: "HS384", key: key)
//    }
//
//    /// Creates an HS512 JWT signer with the supplied key
//    public static func hs512(key: CryptoData) -> JWTSigner {
//        return hmac(HMAC.SHA512, name: "HS512", key: key)
//    }
//
//    /// Creates an HMAC-based `CustomJWTAlgorithm` and `JWTSigner`.
//    private static func hmac(_ hmac: HMAC, name: String, key: CryptoData) -> JWTSigner {
//        let alg = CustomJWTAlgorithm(name: name, sign: { plaintext in
//            return try hmac.authenticate(plaintext, key: key)
//        }, verify: { signature, plaintext in
//            return try hmac.authenticate(plaintext, key: key) == signature.convertToData()
//        })
//        return .init(algorithm: alg)
//    }
//}

/// MARK: RSA
//
//extension JWTSigner {
//    /// Creates an RS256 JWT signer with the supplied key
//    public static func rs256(key: RSAKey) -> JWTSigner {
//        return rsa(RSA.SHA256, name: "RS256", key: key)
//    }
//
//    /// Creates an RS384 JWT signer with the supplied key
//    public static func rs384(key: RSAKey) -> JWTSigner {
//        return rsa(RSA.SHA384, name: "RS384", key: key)
//    }
//
//    /// Creates an RS512 JWT signer with the supplied key
//    public static func rs512(key: RSAKey) -> JWTSigner {
//        return rsa(RSA.SHA512, name: "RS512", key: key)
//    }
//
//    /// Creates an RSA-based `CustomJWTAlgorithm` and `JWTSigner`.
//    private static func rsa(_ rsa: RSA, name: String, key: RSAKey) -> JWTSigner {
//        let alg = CustomJWTAlgorithm(name: name, sign: { plaintext in
//            return try rsa.sign(plaintext, key: key)
//        }, verify: { signature, plaintext in
//            return try rsa.verify(signature, signs: plaintext, key: key)
//        })
//        return .init(algorithm: alg)
//    }
//}
