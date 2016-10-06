import Foundation
import Node

public protocol Claim {
    static var name: String { get }
    func verify(_ : Node) -> Bool
}

extension Claim {

    public func verify(_ dict: [String: Node]) -> Bool {
        return dict[type(of: self).name].map(verify) ?? false
    }
}

public protocol EqualityClaim: Claim, NodeFailableInitializable {
    associatedtype T: Equatable
    var value: T { get }
}

extension EqualityClaim {

    public func verify(_ node: Node) -> Bool {
        guard let other = type(of: self).init(node) else {
            return false
        }

        return self.value == other.value
    }
}

public protocol DateWithLeewayClaim: DateBacked, Claim {
    var leeway: TimeInterval { get }
    init(_ value: Date, leeway: TimeInterval)
    func verify(_ other: Date) -> Bool
}

extension DateWithLeewayClaim {

    public init(_ value: Date) {
        self.init(value, leeway: 0)
    }
}

extension DateWithLeewayClaim {

    public func verify(_ node: Node) -> Bool {
        guard let other = Self(node) else {
            return false
        }

        return verify(other.value)
    }
}
