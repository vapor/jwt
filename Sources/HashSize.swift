import CLibreSSL
import Foundation
import Hash
import HMAC

func newECKeyPair(_ hashSize: HashSize) throws -> OpaquePointer {
    guard
        let ecKey = EC_KEY_new_by_curve_name(hashSize.curve),
        let privateBytes = try Data(base64Encoded: hashSize.key)?.makeBytes() else {
            throw JWTError.couldNotGenerateKey
    }
    var privateNum = BIGNUM()

    // Set private key

    BN_init(&privateNum)
    BN_bin2bn(privateBytes, Int32(privateBytes.count), &privateNum)
    EC_KEY_set_private_key(ecKey, &privateNum)

    // Derive public key

    let context = BN_CTX_new()
    BN_CTX_start(context)

    let group = EC_KEY_get0_group(ecKey)
    let publicKey = EC_POINT_new(group)
    EC_POINT_mul(group, publicKey, &privateNum, nil, nil, context)
    EC_KEY_set_public_key(ecKey, publicKey)

    // Release resources

    EC_POINT_free(publicKey)
    BN_CTX_end(context)
    BN_CTX_free(context)
    BN_clear_free(&privateNum)

    return ecKey
}

func newECPublicKey(_ hashSize: HashSize) throws -> OpaquePointer {
    guard let publicBytes = try Data(base64Encoded: hashSize.key)?.makeBytes() else {
        throw JWTError.couldNotGenerateKey
    }

    var ecKey = EC_KEY_new_by_curve_name(hashSize.curve)
    var publicBytesPointer: UnsafePointer? = UnsafePointer<UInt8>(publicBytes)

    if let ecKey = o2i_ECPublicKey(&ecKey, &publicBytesPointer, publicBytes.count) {
        return ecKey
    } else {
        throw JWTError.couldNotGenerateKey
    }
}

enum HashSize {
    case _256(String)
    case _384(String)
    case _512(String)
}

extension HashSize {

    init(_ string: String, key: String) throws {
        switch string {
        case "256": self = ._256(key)
        case "384": self = ._384(key)
        case "512": self = ._512(key)
        default:
            throw JWTError.unsupportedAlgorithm
        }
    }

    var curve: Int32 {
        switch self {
        case ._256: return NID_secp256k1
        case ._384: return NID_secp384r1
        case ._512: return NID_secp521r1
        }
    }

    var key: String {
        switch self {
        case ._256(let key), ._384(let key), ._512(let key):
            return key
        }
    }

    var shaHashMethod: Hash.Method {
        switch self {
        case ._256: return .sha256
        case ._384: return .sha384
        case ._512: return .sha512
        }
    }

    var shaHMACMethod: HMAC.Method {
        switch self {
        case ._256: return .sha256
        case ._384: return .sha384
        case ._512: return .sha512
        }
    }

    var string: String {
        switch self {
        case ._256: return "256"
        case ._384: return "384"
        case ._512: return "512"
        }
    }
}
