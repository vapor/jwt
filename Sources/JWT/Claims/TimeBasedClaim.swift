import Foundation
import Node

public protocol TimeBasedClaim: SecondsBacked, Claim {
    var createTimestamp: () -> Seconds { get }

    init(createTimestamp: @escaping () -> Seconds, leeway: Seconds)
    func verify(_ other: Seconds) -> Bool
}

extension TimeBasedClaim {
    public init(
        createDate: @escaping () -> Date = Date.init,
        leeway: Seconds = 0) {
        self.init(
            createTimestamp: { Seconds(createDate().timeIntervalSince1970) },
            leeway: leeway)
    }

    public init(
        date: Date,
        leeway: Seconds = 0) {
        self.init(
            createDate: { date },
            leeway: leeway)
    }

    public init(
        seconds: Seconds,
        leeway: Seconds = 0) {
        self.init(
            createTimestamp: { seconds },
            leeway: leeway)
    }

    public init(seconds: Seconds) {
        self.init(createTimestamp: { seconds }, leeway: 0)
    }

    public func verify(_ node: Node) -> Bool {
        do {
            let other = try Self(node: node)
            return verify(other.value)
        } catch {
            return false
        }
    }

    public var value: Seconds {
        return createTimestamp()
    }
}
