import Foundation
import Node

public protocol SecondsWithLeewayClaim: SecondsBacked, Claim {
    var leeway: Seconds { get }
    init(_ value: Seconds, leeway: Seconds)
    func verify(_ other: Seconds) -> Bool
}

extension SecondsWithLeewayClaim {
    public init(_ date: Date = Date(), leeway: Seconds = 0) {
        self.init(Seconds(date.timeIntervalSince1970), leeway: leeway)
    }

    public init(_ value: Seconds) {
        self.init(value, leeway: 0)
    }

    public func verify(_ node: Node) -> Bool {
        guard let other = Self(node) else {
            return false
        }

        return verify(other.value)
    }
}
