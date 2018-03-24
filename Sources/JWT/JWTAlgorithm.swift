import Crypto
import Foundation

/// The algorithm to use for signing
public protocol JWTAlgorithm {
    /// Unique JWT-standard name for this algorithm.
    var jwtAlgorithmName: String { get }

    /// Creates a signature from the supplied plaintext.
    func sign(_ plaintext: Data) throws -> Data

    /// Returns true if the signature was creating by signing the plaintext.
    func verify(_ signature: Data, signs plaintext: Data) throws -> Bool
}

extension JWTAlgorithm {
    /// See `JWTAlgorithm.verify(_:signs)`
    public func verify(_ signature: Data, signs plaintext: Data) throws -> Bool {
        return try sign(plaintext) == signature
    }
}

extension RSA: JWTAlgorithm {
    /// See JWTAlgorithm.jwtAlgorithmName
    public var jwtAlgorithmName: String {
        switch digestAlgorithm {
        case .sha1: return "RS1"
        case .sha224: return "RS224"
        case .sha256: return "RS256"
        case .sha384: return "RS384"
        case .sha512: return "RS512"
        default:
            return "Unknown" // this should never be reached
        }
    }

    /// See `JWTAlgorithm.sign`
    public func sign(_ plaintext: Data) throws -> Data {
        return try sign(plaintext as LosslessDataConvertible)
    }

    /// See `JWTAlgorithm.verify`
    public func verify(_ signature: Data, signs plaintext: Data) throws -> Bool {
        return try verify(signature as LosslessDataConvertible, signs: plaintext as LosslessDataConvertible)
    }
}

public struct HMACAlgorithm: JWTAlgorithm {
    /// HMAC variant to use
    public let variant: HMACAlgorithmVariant

    /// The HMAC key
    public let key: Data

    /// See JWTAlgorithm.jwtAlgorithmName
    public var jwtAlgorithmName: String {
        switch variant {
        case .sha256: return "HS256"
        case .sha384: return "HS384"
        case .sha512: return "HS512"
        }
    }

    /// Create a new HMAC algorithm
    public init(_ variant: HMACAlgorithmVariant, key: Data) {
        self.variant = variant
        self.key = key
    }

    /// See JWTAlgorithm.makeCiphertext
    public func sign(_ plaintext: Data) throws -> Data {
        switch variant {
        case .sha256: return try HMAC.SHA256.authenticate(plaintext, key: key)
        case .sha384: return try HMAC.SHA384.authenticate(plaintext, key: key)
        case .sha512: return try HMAC.SHA512.authenticate(plaintext, key: key)
        }
    }
}

/// Supported HMAC algorithm variants
public enum HMACAlgorithmVariant {
    case sha256
    case sha384
    case sha512
}

extension DigestAlgorithm: Equatable {
    public static func == (lhs: DigestAlgorithm, rhs: DigestAlgorithm) -> Bool {
        return rhs.type == lhs.type
    }
}
