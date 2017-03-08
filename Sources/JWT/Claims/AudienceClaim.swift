import Foundation
import Node

public struct AudienceClaim {
    fileprivate let value: Set<String>

    public init(string: String) {
        self.value = [string]
    }

    public init(strings: Set<String>) {
        self.value = strings
    }

    init?(node: Node) {
        if let string = node.string {
            self.init(string: string)
        } else if let array = node.array?.flatMap({ $0.string }) {
            self.init(strings: Set(array))
        } else {
            return nil
        }
    }
}

extension AudienceClaim: ExpressibleByStringLiteral {
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

extension AudienceClaim: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: String...) {
        self.init(strings: Set(elements))
    }
}

extension AudienceClaim: Claim {
    public static let name = "aud"

    public func verify(_ node: Node) -> Bool {
        guard let other = AudienceClaim(node: node) else {
            return false
        }

        return value.intersection(other.value).count == other.value.count
    }

    public var node: Node {
        let strings = value.array.map(StructuredData.string)
        return Node(
            .array(strings),
            in: nil
        )
    }
}
