import Core
import Foundation

struct Base64URL: Encoding {

    private let base64URLTranscoder: Base64URLTranscoding

    init(base64URLTranscoder: Base64URLTranscoding = Base64URLTranscoder()) {
        self.base64URLTranscoder = base64URLTranscoder
    }

    func encode(_ bytes: Bytes) throws -> String {
        guard let base64URL = base64URLTranscoder.base64URLEncode( bytes.base64String) else {
            throw JWTError.encoding
        }
        return base64URL
    }

    func decode(_ base64URLEncoded: String) throws -> Bytes {
        guard
            let base64Encoded = base64URLTranscoder.base64Encode(base64URLEncoded),
            let data = Data(base64Encoded: base64Encoded) else {
                throw JWTError.decoding
        }
        return try data.makeBytes()
    }
}

protocol Base64URLTranscoding {
    func base64Encode(_: String) -> String?
    func base64URLEncode(_: String) -> String?
}

struct Base64URLTranscoder: Base64URLTranscoding {

    func base64Encode(_ string: String) -> String? {
        var converted = string.utf8CString.map { char -> CChar in
            switch char {
            case 45: // '-'
                return  43 // '+'
            case 95: // '_'
                return 47 // '/'
            default:
                return char
            }
        }
        guard let unpadded = String(utf8String: &converted) else {
            return nil
        }

        let characterCount = unpadded.utf8CString.count - 1 // ignore last /0

        let paddingCount = 4 - (characterCount % 4)
        let padding = Array(repeating: "=", count: paddingCount).joined()

        return unpadded + padding
    }

    func base64URLEncode(_ string: String) -> String? {
        var converted = string.utf8CString.flatMap { char -> CChar? in
            switch char {
            case 43: // '+'
                return 45 // '-'
            case 47: // '/'
                return 95 // '_'
            case 61: // '='
                return nil
            default:
                return char
            }
        }
        return String(utf8String: &converted)
    }
}
