import Foundation
import Node

public struct NotBeforeClaim: TimeBasedClaim {
    public static var name = "nbf"

    let createTimestamp: () -> Seconds
    let leeway: Seconds

    public init(
        createTimestamp: @escaping () -> Seconds,
        leeway: Seconds = 0) {
        self.createTimestamp = createTimestamp
        self.leeway = leeway
    }

    public func verify(_ other: Seconds) -> Bool {
        return other - leeway <= value
    }
}
