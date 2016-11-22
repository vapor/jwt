import CLibreSSL
import Core
import Hash

public enum HashMethod {
    case sha256
    case sha384
    case sha512
}

extension HashMethod {
    var type: Int32 {
        switch self {
        case .sha256: return NID_sha256
        case .sha384: return NID_sha384
        case .sha512: return NID_sha512
        }
    }

    var method: Hash.Method {
        switch self {
        case .sha256: return .sha256
        case .sha384: return .sha384
        case .sha512: return .sha512
        }
    }
}

public struct RS256: RSASigner {
    public let key: Bytes
    public let hashMethod = HashMethod.sha256

    public init(key: Bytes) {
        self.key = key
    }
}

public struct RS384: RSASigner {
    public let key: Bytes
    public let hashMethod = HashMethod.sha384

    public init(key: Bytes) {
        self.key = key
    }
}

public struct RS512: RSASigner {
    public let key: Bytes
    public let hashMethod = HashMethod.sha512

    public init(key: Bytes) {
        self.key = key
    }
}

public protocol RSASigner: Key, Signer {
    var hashMethod: HashMethod { get }
}

extension RSASigner {
    public func sign(_ message: Bytes) throws -> Bytes {
        guard let rsa = key.withUnsafeBufferPointer({ p -> UnsafeMutablePointer<RSA>! in
            var baseAddress = p.baseAddress
            return d2i_RSAPrivateKey(nil, &baseAddress, key.count)
        }) else {
            throw JWTError.createKey
        }

        var siglen: UInt32 = 0
        var sig = Bytes(repeating: 0, count: Int(RSA_size(rsa)))

        let digest = try Hash(hashMethod.method, message).hash()

        RSA_sign(hashMethod.type, digest, UInt32(digest.count), &sig, &siglen, rsa)

        return sig
    }

    public func verifySignature(_ signature: Bytes, message: Bytes) throws -> Bool {
        guard let rsa = key.withUnsafeBufferPointer({ p -> UnsafeMutablePointer<RSA>! in
            var baseAddress = p.baseAddress
            return d2i_RSA_PUBKEY(nil, &baseAddress, key.count)
        }) else {
            throw JWTError.createPublicKey
        }

        let digest = try Hash(hashMethod.method, message).hash()

        return RSA_verify(hashMethod.type, digest, UInt32(digest.count), signature,
                          UInt32(signature.count), rsa) == 1
    }
}
