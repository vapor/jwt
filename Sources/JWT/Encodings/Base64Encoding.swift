import Core

public struct Base64Encoding: Encoding {

    public init() {}

    public func encode(_ bytes: Bytes) throws -> String {
        return Base64Encoder.shared.encode(bytes).string
    }

    public func decode(_ base64Encoded: String) throws -> Bytes {
        return Base64Encoder.shared.decode(base64Encoded.bytes)
    }
}
