typealias StringBase64 = String
typealias StringBase64URL = String

extension StringBase64 {

    var base64URL: StringBase64URL? {
        var converted = utf8CString.flatMap { char -> CChar? in
            switch char {
            case 43: // '+'
                return 45 // '-'
            case 47: // '/'
                return 95// '_'
            case 61: // '='
                return nil
            default:
                return char
            }
        }
        return StringBase64URL(utf8String: &converted)
    }
}

extension StringBase64URL {

    var base64: StringBase64? {
        var converted = utf8CString.map { char -> CChar in
            switch char {
            case 45: // '-'
                return  43 // '+'
            case 95: // '_'
                return 47// '/'
            default:
                return char
            }
        }
        return StringBase64(utf8String: &converted)
    }
}
