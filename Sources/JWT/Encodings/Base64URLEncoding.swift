import Core
import Foundation

public struct Base64URLEncoding: Encoding {
    public init() {}

    public func encode(_ bytes: Bytes) throws -> String {
        return Base64Encoder.url.encode(bytes).string
    }
    
    public func decode(_ base64Encoded: String) throws -> Bytes {
        return Base64Encoder.url.decode(base64Encoded.bytes)
    }
}
