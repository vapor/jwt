import Core
import HMAC

public final class HS256: HMACSigner {
    let key: Bytes
    let method = HMAC.Method.sha256

    public init(key: Bytes) {
        self.key = key
    }
}

public final class HS384: HMACSigner {
    let key: Bytes
    let method = HMAC.Method.sha384

    public init(key: Bytes) {
        self.key = key
    }
}

public final class HS512: HMACSigner {
    let key: Bytes
    let method = HMAC.Method.sha256

    public init(key: Bytes) {
        self.key = key
    }
}

protocol HMACSigner: Signer, BytesConvertible {
    init(key: Bytes)
    var key: Bytes { get }
    var method: HMAC.Method { get }
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
            throw JWTError.verificationFailed
        }
    }
}
