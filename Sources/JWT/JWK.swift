import Foundation
import Crypto

/// A JSON Web Key.
///
/// Read specification (RFC 7517) https://tools.ietf.org/html/rfc7517.
public struct JWK: Codable {
    /// The `kty` (key type) parameter identifies the cryptographic algorithm family used with the key, such as `RSA` or `EC`. The `kty` value is a case-sensitive string.
    public var kty: String

    /// The `use` (public key use) parameter identifies the intended use of the public key. The `use` parameter is employed to indicate whether a public key is used for encrypting data or verifying the signature on data.
    public var use: PublicKeyUse?

    /// The `key_ops` (key operations) parameter identifies the operation(s) for which the key is intended to be used. The `key_ops` parameter is intended for use cases in which public, private, or symmetric keys may be present.
    public var keyOps: [KeyOperation]?

    /// The `alg` (algorithm) parameter identifies the algorithm intended for use with the key. The `alg` value is a case-sensitive ASCII string.
    public var alg: String?

    /**
     The `kid` (key ID) parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.

     The structure of the `kid` value is unspecified. When `kid` values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct `kid` values.

     (One example in which different keys might use the same `kid` value is if they have different `kty` (key type) values but are considered to be equivalent alternatives by the application using them.)

     The `kid` value is a case-sensitive string.
     */
    public var kid: String?

    /// The `x5u` (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280].
    public var x5u: String?

    /// The `x5c` (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates [RFC5280].
    public var x5c: [String]?

    /// The `x5t` (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints.
    public var x5t: String?

    /// The `x5t#S256` (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].
    public var x5tS256: String?

    // RSA keys
    // Represented as the base64url encoding of the value’s unsigned big endian representation as an octet sequence.

    /// Modulus.
    public var n: String?

    /// Exponent.
    public var e: String?

    /// Private exponent.
    public var d: String?

    /// First prime factor.
    public var p: String?

    /// Second prime factor.
    public var q: String?

    /// First factor CRT exponent.
    public var dp: String?

    /// Second factor CRT exponent.
    public var dq: String?

    /// First CRT coefficient.
    public var qi: String?

    /// Other primes info.
    public var oth: OthType?

    // EC DSS keys

    public var crv: String?

    public var x: String?

    public var y: String?

    public enum OthType: String, Codable {
        case r
        case d
        case t
    }

    private enum CodingKeys: String, CodingKey {
        case kty
        case use
        case keyOps = "key_ops"
        case alg
        case kid
        case x5u
        case x5c
        case x5t
        case x5tS256 = "x5t#S256"
        case n
        case e
        case d
        case p
        case q
        case dp
        case dq
        case qi
        case oth
        case crv
        case x
        case y
    }

    public init(
        kty: String,
        use: PublicKeyUse? = nil,
        keyOps: [KeyOperation]? = nil,
        alg: String? = nil,
        kid: String? = nil,
        x5u: String? = nil,
        x5c: [String]? = nil,
        x5t: String? = nil,
        x5tS256: String? = nil,
        n: String? = nil,
        e: String? = nil,
        d: String? = nil,
        p: String? = nil,
        q: String? = nil,
        dp: String? = nil,
        dq: String? = nil,
        qi: String? = nil,
        oth: OthType? = nil,
        crv: String? = nil,
        x: String? = nil,
        y: String? = nil
    ) {
        self.kty = kty
        self.use = use
        self.keyOps = keyOps
        self.alg = alg
        self.kid = kid
        self.x5u = x5u
        self.x5c = x5c
        self.x5t = x5t
        self.x5tS256 = x5tS256
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qi = qi
        self.oth = oth
        self.crv = crv
        self.x = x
        self.y = y
    }
}

extension JWTSigner {

    /// Creates a JWT signer with the supplied JWK
    public static func jwk(key: JWK) throws -> JWTSigner {
        switch key.kty.lowercased() {
        case "rsa":
            guard let n = key.n else {
                throw JWTError(identifier: "missingModulus", reason: "Modulus not specified for JWK RSA key.")
            }
            guard let e = key.e else {
                throw JWTError(identifier: "missingExponent", reason: "Exponent not specified for JWK RSA key.")
            }

            guard let algorithm = key.alg?.lowercased() else {
                throw JWTError(identifier: "missingAlgorithm", reason: "Algorithm missing for JWK RSA key.")
            }

            let rsaKey = try RSAKey.components(n: n, e: e, d: key.d)

            switch algorithm {
            case "rs256":
                return JWTSigner.rs256(key: rsaKey)
            case "rs384":
                return JWTSigner.rs384(key: rsaKey)
            case "rs512":
                return JWTSigner.rs512(key: rsaKey)
            default:
                throw JWTError(identifier: "invalidAlgorithm", reason: "Algorithm \(String(describing: key.alg)) not supported for JWK RSA key.")
            }
        default:
            throw JWTError(identifier: "invalidKeyType", reason: "Key type \(String(describing: key.kty)) not supported.")
        }
    }
}
