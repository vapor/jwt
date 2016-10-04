import Foundation
import JSON

extension JSON {

    init(base64Encoded: String) throws {
        guard let data = Data(base64Encoded: base64Encoded) else {
            throw JWTError.notBase64Encoded
        }

        try self.init(bytes: try data.makeBytes())
    }

    func base64String() throws -> String {
        return try makeBytes().base64String
    }
}
