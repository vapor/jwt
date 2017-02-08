import Core
import JSON

public protocol Encoding {
    func decode(_ : String) throws -> Bytes
    func encode(_ : Bytes) throws -> String
}

extension Encoding {
    func decode(_ string: String) throws -> Node {
        return try JSON(bytes: decode(string)).node
    }

    func encode(_ value: Node) throws -> String {
        return try encode(try JSON(value).makeBytes())
    }
}
