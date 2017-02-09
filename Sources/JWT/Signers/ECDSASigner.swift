import CLibreSSL
import Core
import Foundation
import Hash

public class ES256: ECDSASigner {
    public let curve = NID_X9_62_prime256v1
    public let key: Bytes
    public let method = Hash.Method.sha256

    public required init(key: Bytes) {
        self.key = key
    }
}

public class ES384: ECDSASigner {
    public let curve = NID_secp384r1
    public let key: Bytes
    public let method = Hash.Method.sha384

    public required init(key: Bytes) {
        self.key = key
    }
}

public class ES512: ECDSASigner {
    public let curve = NID_secp521r1
    public let key: Bytes
    public let method = Hash.Method.sha512

    public required init(key: Bytes) {
        self.key = key
    }
}

public protocol ECDSASigner: Signer, BytesConvertible {
    init(key: Bytes)
    var key: Bytes { get }
    var curve: Int32 { get }
    var method: Hash.Method { get }
}

extension ECDSASigner {
    public init(bytes: Bytes) {
        self.init(key: bytes)
    }

    public func makeBytes() -> Bytes {
        return key
    }
}

extension ECDSASigner {
    public func sign(message: Bytes) throws -> Bytes {
        var digest = try Hash(method, message).hash()
        let ecKey = try newECKeyPair()

        guard let signature = ECDSA_do_sign(&digest, Int32(digest.count), ecKey) else {
            throw JWTError.signing
        }

        var derEncodedSignature: UnsafeMutablePointer<UInt8>? = nil
        let derLength = i2d_ECDSA_SIG(signature, &derEncodedSignature)

        guard let derCopy = derEncodedSignature, derLength > 0 else {
            throw JWTError.signing
        }

        var derBytes = [UInt8](repeating: 0, count: Int(derLength))

        for b in 0..<Int(derLength) {
            derBytes[b] = derCopy[b]
        }

        return derBytes
    }

    public func verify(signature der: Bytes, message: Bytes) throws {
        var signaturePointer: UnsafePointer? = UnsafePointer(der)
        let signature = d2i_ECDSA_SIG(nil, &signaturePointer, der.count)
        let digest = try Hash(method, message).hash()
        let ecKey = try newECPublicKey()
        let verified = ECDSA_do_verify(digest, Int32(digest.count), signature, ecKey)
        guard verified == 1 else {
            throw JWTError.verificationFailed
        }
    }
}

fileprivate extension ECDSASigner {
    func newECKey() throws -> OpaquePointer {
        guard let ecKey = EC_KEY_new_by_curve_name(curve) else {
            throw JWTError.createKey
        }
        return ecKey
    }

    func newECKeyPair() throws -> OpaquePointer {
        var privateNum = BIGNUM()

        // Set private key

        BN_init(&privateNum)
        BN_bin2bn(key, Int32(key.count), &privateNum)
        let ecKey = try newECKey()
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

    func newECPublicKey() throws -> OpaquePointer {
        var ecKey: OpaquePointer? = try newECKey()
        var publicBytesPointer: UnsafePointer? = UnsafePointer<UInt8>(key)

        if let ecKey = o2i_ECPublicKey(&ecKey, &publicBytesPointer, key.count) {
            return ecKey
        } else {
            throw JWTError.createPublicKey
        }
    }
}
