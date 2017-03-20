import Core

public struct Base64URLEncoding: Encoding {
    private let base64URLTranscoder: Base64URLTranscoding

    public init() {
        self.init(base64URLTranscoder: Base64URLTranscoder())
    }

    init(base64URLTranscoder: Base64URLTranscoding) {
        self.base64URLTranscoder = base64URLTranscoder
    }

    public func encode(_ bytes: Bytes) throws -> String {
        return bytes.base64URLEncoded.makeString()
    }

    public func decode(_ base64URLEncoded: String) throws -> Bytes {
        return base64URLEncoded.makeBytes().base64URLDecoded
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

        let paddingRemainder = (characterCount % 4)
        let paddingCount = paddingRemainder > 0 ? 4 - paddingRemainder : 0
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
