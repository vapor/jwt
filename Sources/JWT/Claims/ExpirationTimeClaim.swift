import Foundation
import Node

public struct ExpirationTimeClaim: TimeBasedClaim {
    public static var name = "exp"

    let createTimestamp: () -> Seconds
    let leeway: Seconds

    public init(createTimestamp: @escaping () -> Seconds, leeway: Seconds) {
        self.createTimestamp = createTimestamp
        self.leeway = leeway
    }

    public func verify(_ other: Seconds) -> Bool {
        return other + leeway >= value
    }
}
