import Foundation

extension JWTSigner {
    /// Creates a JWT sign from the supplied JWK json string.
    public static func jwk(json: String) throws -> JWTSigner {
        let jwk = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
        return try self.jwk(jwk)
    }
    
    /// Creates a JWT signer with the supplied JWK
    public static func jwk(_ key: JWK) throws -> JWTSigner {
        switch key.keyType {
        case .rsa:
            guard let modulus = key.modulus else {
                throw JWTError.invalidJWK
            }
            guard let exponent = key.exponent else {
                throw JWTError.invalidJWK
            }
            guard let algorithm = key.algorithm else {
                throw JWTError.invalidJWK
            }
            
            guard let rsaKey = RSAKey(
                modulus: modulus,
                exponent: exponent,
                privateExponent: key.privateExponent
            ) else {
                throw JWTError.invalidJWK
            }
            
            switch algorithm {
            case .rs256:
                return JWTSigner.rs256(key: rsaKey)
            case .rs384:
                return JWTSigner.rs384(key: rsaKey)
            case .rs512:
                return JWTSigner.rs512(key: rsaKey)
            }
        }
    }
}
