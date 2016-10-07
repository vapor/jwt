import Core
import Foundation

struct Base64Encoding: Encoding {

    func encode(_ bytes: Bytes) throws -> String {
        return bytes.base64String
    }

    func decode(_ base64Encoded: String) throws -> Bytes {
        guard let data = Data(base64Encoded: base64Encoded) else {
            throw JWTError.decoding
        }
        return try data.makeBytes()
    }
}
