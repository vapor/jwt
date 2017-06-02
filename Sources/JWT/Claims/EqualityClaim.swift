import Node

public protocol EqualityClaim: Claim, NodeInitializable {
    associatedtype T: Equatable
    var value: T { get }
}

extension EqualityClaim {
    public func verify(_ node: Node) -> Bool {
        do {
            let other = try type(of: self).init(node: node)
            return self.value == other.value
        } catch {
            return false
        }
    }
}
