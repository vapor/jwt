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

public typealias CRSAKey = UnsafeMutablePointer<RSA>

public enum RSAKey {
    case `public`(CRSAKey)
    case `private`(CRSAKey)

    public init(_ rawKey: Bytes) throws {
        if let rsa = rawKey.withUnsafeBufferPointer({ p -> CRSAKey! in
            var baseAddress = p.baseAddress
            return d2i_RSAPrivateKey(nil, &baseAddress, rawKey.count)
        }) {
            self = .private(rsa)
        } else if let rsa = rawKey.withUnsafeBufferPointer({ p -> CRSAKey! in
            var baseAddress = p.baseAddress
            return d2i_RSA_PUBKEY(nil, &baseAddress, rawKey.count)
        }) {
            self = .public(rsa)
        } else {
            throw JWTError.createKey
        }
    }

    var cKey: CRSAKey {
        switch self {
        case .public(let cKey):
            return cKey
        case .private(let cKey):
            return cKey
        }
    }
}

public class RS256: RSASigner {
    public let key: RSAKey
    public let hashMethod = HashMethod.sha256

    public required init(key: Bytes) throws {
        self.key = try RSAKey(key)
    }
}

public class RS384: RSASigner {
    public let key: RSAKey
    public let hashMethod = HashMethod.sha384

    public required init(key: Bytes) throws {
        self.key = try RSAKey(key)
    }
}

public class RS512: RSASigner {
    public let key: RSAKey
    public let hashMethod = HashMethod.sha512

    public required init(key: Bytes) throws {
        self.key = try RSAKey(key)
    }
}

public protocol RSASigner: Signer, BytesInitializable {
    var key: RSAKey { get }
    var hashMethod: HashMethod { get }
    init(key: Bytes) throws
}

extension RSASigner {
    public init(bytes: Bytes) throws {
        try self.init(key: bytes)
    }
}

extension RSASigner {
    public func sign(message: Bytes) throws -> Bytes {
        guard case .private(let cKey) = key else {
            throw JWTError.privateKeyRequired
        }

        var siglen: UInt32 = 0
        var sig = Bytes(
            repeating: 0,
            count: Int(RSA_size(cKey))
        )

        let digest = try Hash(hashMethod.method, message).hash()

        RSA_sign(
            hashMethod.type,
            digest,
            UInt32(digest.count),
            &sig,
            &siglen,
            cKey
        )

        return sig
    }

    public func verify(signature: Bytes, message: Bytes) throws {
        let digest = try Hash(hashMethod.method, message).hash()

        let result = RSA_verify(
            hashMethod.type,
            digest,
            UInt32(digest.count),
            signature,
            UInt32(signature.count),
            key.cKey
        )

        guard result == 1 else {
            throw JWTError.verificationFailed
        }
    }
}
