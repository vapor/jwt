import Foundation
import Node

@available(*, deprecated, message: "Use MultipleAudienceClaim or SingleAudienceClaim instead.")
public typealias AudienceClaim = MultipleAudienceClaim

public struct MultipleAudienceClaim: NodeFailableInitializable {
    fileprivate let value: Set<String>

    public init(string: String) {
        self.value = [string]
    }

    public init(strings: Set<String>) {
        self.value = strings
    }

    public init?(_ node: Node) {
        if let string = node.string {
            self.init(string: string)
        } else if let array = node.array?.flatMap({ $0.string }) {
            self.init(strings: Set(array))
        } else {
            return nil
        }
    }
}

extension MultipleAudienceClaim: ExpressibleByStringLiteral {
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

extension MultipleAudienceClaim: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: String...) {
        self.init(strings: Set(elements))
    }
}

extension MultipleAudienceClaim: Claim {
    public static let name = "aud"

    public func verify(_ node: Node) -> Bool {
        guard let other = MultipleAudienceClaim(node) else {
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
