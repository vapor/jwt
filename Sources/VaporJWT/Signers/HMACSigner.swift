import Core
import HMAC

public struct HS256: HMACSigner {

    public let key: Bytes
    public let method = HMAC.Method.sha256

    public init(key: Bytes) {
        self.key = key
    }
}

public struct HS384: HMACSigner {

    public let key: Bytes
    public let method = HMAC.Method.sha384

    public init(key: Bytes) {
        self.key = key
    }
}

public struct HS512: HMACSigner {

    public let key: Bytes
    public let method = HMAC.Method.sha256

    public init(key: Bytes) {
        self.key = key
    }
}

public protocol HMACSigner: Signer, Key {
    var method: HMAC.Method { get }
}

extension HMACSigner {

    public func sign(_ message: Bytes) throws -> Bytes {
        return try HMAC.make(method, message, key: key)
    }

    public func verifySignature(_ signature: Bytes, message: Bytes) throws -> Bool {
        return try sign(message) == signature
    }
}
