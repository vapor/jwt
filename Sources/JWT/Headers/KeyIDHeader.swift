import Node

public struct KeyIDHeader: Header {
    public static let name = "kid"
    public let node: Node

    public init(identifier: String) {
        node = .string(identifier)
    }
}

public extension JWT {

    public var keyIdentifier: String? {
        return self.headers[KeyIDHeader.name]?.string
    }
}
