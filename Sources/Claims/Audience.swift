import Foundation
import Node

public struct Audience {

    fileprivate let value: Set<String>

    public init(_ string: String) {
        self.value = [string]
    }

    public init(_ strings: Set<String>) {
        self.value = strings
    }

    init?(_ node: Node) {
        switch node {
        case .string(let string):
            self.init(string)
        case .array(let nodes):
            let strings = nodes.flatMap { (node: Node) -> String? in
                if case .string(let string) = node {
                    return string
                }
                return nil
            }
            self.init(Set(strings))
        default:
            return nil
        }
    }
}

extension Audience: ExpressibleByStringLiteral {

    public init(stringLiteral value: String) {
        self.init(value)
    }

    public init(unicodeScalarLiteral value: String) {
        self.init(value)
    }

    public init(extendedGraphemeClusterLiteral value: String) {
        self.init(value)
    }
}

extension Audience: ExpressibleByArrayLiteral {

    public init(arrayLiteral elements: String...) {
        self.init(Set(elements))
    }
}

extension Audience: Claim {

    public static let name = "aud"

    public func verify(_ node: Node) -> Bool {
        guard let other = Audience(node) else {
            return false
        }

        return value.intersection(other.value).count == other.value.count
    }
}
