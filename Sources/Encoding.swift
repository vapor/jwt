import Core
import Foundation
import JSON

public enum Encoding {
    case base64
    case base64URL
}

extension Encoding {

    func encode(_ value: BytesRepresentable) throws -> String {
        return try encode(try value.makeBytes())
    }

    func encode(_ bytes: Bytes) throws -> String {
        let base64 = bytes.base64String

        switch self {
        case .base64:
            return base64
        case .base64URL:
            guard let base64URL = base64.base64URL else {
                throw JWTError.notBase64Encoded
            }
            return base64URL
        }
    }

    func decode(_ string: String) throws -> JSON {
        return try JSON(bytes: decode(string))
    }

    func decode(_ string: String) throws -> Bytes {
        let processed: String?

        switch self {
        case .base64:
            processed = string
        case .base64URL:
            processed = string.base64
        }

        guard let string = processed, let data = Data(base64Encoded: string) else {
            throw JWTError.notBase64Encoded
        }
        return try data.makeBytes()
    }
}
