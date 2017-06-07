import Node

public struct KeyIDHeader: Header {
    public static let name = "kid"
    public let node: Node

    init(identifier: String) {
        kid = .string(identifier)
    }
}
