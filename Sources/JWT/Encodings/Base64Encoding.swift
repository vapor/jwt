import Core

public struct Base64Encoding: Encoding {

    public init() {}

    public func encode(_ bytes: Bytes) throws -> String {
        return bytes.base64Encoded.makeString()
    }

    public func decode(_ base64Encoded: String) throws -> Bytes {
        return base64Encoded.makeBytes().base64Decoded
    }
}
