import Core
import JSON

public protocol Encoding {
    func decode(_ : String) throws -> Bytes
    func encode(_ : Bytes) throws -> String
}

extension Encoding {
    func decode(_ string: String) throws -> JSON {
        return try JSON(bytes: decode(string))
    }

    func encode(_ value: BytesRepresentable) throws -> String {
        return try encode(try value.makeBytes())
    }
}
