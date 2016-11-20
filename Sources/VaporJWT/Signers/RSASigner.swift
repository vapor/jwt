import CLibreSSL
import Core
import Hash

public struct RS256: RSASigner {
    public let key: Bytes
    public let type = NID_sha256

    public init(key: Bytes) {
        self.key = key
    }
}

public struct RS384: RSASigner {
    public let key: Bytes
    public let type = NID_sha384

    public init(key: Bytes) {
        self.key = key
    }
}

public struct RS512: RSASigner {
    public let key: Bytes
    public let type = NID_sha512

    public init(key: Bytes) {
        self.key = key
    }
}

public protocol RSASigner: Key, Signer {
    var type: Int32 { get }
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

        RSA_sign(type, message, UInt32(message.count), &sig, &siglen, rsa)

        return sig
    }

    public func verifySignature(_ signature: Bytes, message: Bytes) throws -> Bool {
        guard let rsa = key.withUnsafeBufferPointer({ p -> UnsafeMutablePointer<RSA>! in
            var baseAddress = p.baseAddress
            return d2i_RSA_PUBKEY(nil, &baseAddress, key.count)
        }) else {
            throw JWTError.createPublicKey
        }

        return RSA_verify(type, message, UInt32(message.count), signature,
                          UInt32(signature.count), rsa) == 1
    }
}
