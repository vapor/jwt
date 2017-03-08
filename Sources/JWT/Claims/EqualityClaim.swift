import Node

protocol EqualityClaim: Claim, PolymorphicInitializable {
    associatedtype T: Equatable
    var value: T { get }
}

extension EqualityClaim {
    public func verify(_ polymorphic: Polymorphic) -> Bool {
        guard let other = type(of: self).init(polymorphic) else {
            return false
        }

        return self.value == other.value
    }
}
