//: [Previous](@previous)
//: ## Encoding
import VaporJWT
import Core
import Foundation

//: In order to use a different encoding than the included `Base64Encoding` and `Base64URLEncoding`, conform to `Encoding`. For example:
struct URLEncoding: Encoding {

    let allowedCharacters: CharacterSet

    init(allowedCharacters: CharacterSet = .alphanumerics) {
        self.allowedCharacters = allowedCharacters
    }

    func decode(_ string: String) throws -> Bytes {
        let s = string as NSString

        return s.removingPercentEncoding?.bytes ?? []
    }

    func encode(_ bytes: Bytes) throws -> String {
        let s = try String(bytes: bytes) as NSString
        return s.addingPercentEncoding(withAllowedCharacters: allowedCharacters) ?? ""
    }
}

let encoded = try URLEncoding().encode("/ wat?".bytes)
try URLEncoding().decode(encoded).string()
