import Node

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
