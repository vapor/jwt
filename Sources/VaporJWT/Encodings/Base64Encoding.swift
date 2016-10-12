import Core
import Foundation

public struct Base64Encoding: Encoding {

    public init() {}

    public func encode(_ bytes: Bytes) throws -> String {
        return bytes.base64String
    }

    public func decode(_ base64Encoded: String) throws -> Bytes {
        guard let data = Data(base64Encoded: base64Encoded) else {
            throw JWTError.decoding
        }
        return try data.makeBytes()
    }
}
