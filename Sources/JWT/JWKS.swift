import Foundation

/// A JSON Web Key Set.
///
/// A JSON object that represents a set of JWKs.
/// Read specification (RFC 7517) https://tools.ietf.org/html/rfc7517.
public struct JWKS: Codable {

    public var keys: [JWK]

    public init(keys: [JWK]) {
        self.keys = keys
    }
}

extension JWTSigners {

    public convenience init(jwks: JWKS, skipAnonymousKeys: Bool = true) throws  {
        self.init()
        for jwk in jwks.keys {
            guard let kid = jwk.kid else {
                if skipAnonymousKeys {
                    continue
                } else {
                    throw JWTError(identifier: "missingKID", reason: "At least a JSON Web Key in the JSON Web Key Set is missing a `kid`.")
                }
            }

            try self.use(JWTSigner.jwk(key: jwk), kid: kid)
        }
    }
}
