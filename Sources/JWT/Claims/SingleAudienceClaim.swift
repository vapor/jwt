public struct SingleAudienceClaim: EqualityClaim {
    public static var name = "aud"
    public let value: String

    public init(string: String) {
        self.value = string
    }

    public init?(_ node: Node) {
        guard let string = node.string else {
            return nil
        }

        self.init(string: string)
    }

    public var node: Node {
        return .string(value)
    }
}

extension SingleAudienceClaim: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        self.init(string: value)
    }

    public init(unicodeScalarLiteral value: String) {
        self.init(string: value)
    }

    public init(extendedGraphemeClusterLiteral value: String) {
        self.init(string: value)
    }
}
