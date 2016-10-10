import Foundation
import Node

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
