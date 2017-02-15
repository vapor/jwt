import Foundation
import Node

protocol TimeBasedClaim: SecondsBacked, Claim {
    var createTimestamp: () -> Seconds { get }

    init(createTimestamp: @escaping () -> Seconds, leeway: Seconds)
    func verify(_ other: Seconds) -> Bool
}

extension TimeBasedClaim {
    init(date: Date = Date(), leeway: Seconds = 0) {
        self.init(seconds:
            Seconds(date.timeIntervalSince1970),
            leeway: leeway)
    }

    init(seconds: Seconds, leeway: Seconds) {
        self.init(createTimestamp: { seconds }, leeway: leeway)
    }

    init(seconds: Seconds) {
        self.init(seconds: seconds, leeway: 0)
    }

    public func verify(_ node: Node) -> Bool {
        guard let other = Self(node: node) else {
            return false
        }

        return verify(other.value)
    }

    var value: Seconds {
        return createTimestamp()
    }
}
