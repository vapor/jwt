import Crypto

public final class HS256: HMACSigner {
    public let key: Bytes
    public let method = HMAC.Method.sha256

    public init(key: Bytes) {
        self.key = key
    }
}

public final class HS384: HMACSigner {
    public let key: Bytes
    public let method = HMAC.Method.sha384

    public init(key: Bytes) {
        self.key = key
    }
}

public final class HS512: HMACSigner {
    public let key: Bytes
    public let method = HMAC.Method.sha512

    public init(key: Bytes) {
        self.key = key
    }
}

public protocol HMACSigner: Signer, BytesConvertible {
    var key: Bytes { get }
    var method: HMAC.Method { get }
    init(key: Bytes)
}

extension HMACSigner {
    public init(bytes: Bytes) {
        self.init(key: bytes)
    }

    public func makeBytes() -> Bytes {
        return key
    }
}

extension HMACSigner {
    public func sign(message: Bytes) throws -> Bytes {
        return try HMAC.make(method, message, key: key)
    }

    public func verify(signature: Bytes, message: Bytes) throws {
        guard try sign(message: message) == signature else {
            throw JWTError.signatureVerificationFailed
        }
    }
}
