import Foundation
import Node

public struct ExpirationTimeClaim: SecondsWithLeewayClaim {
    public static var name = "exp"

    public let leeway: Seconds
    public let value: Seconds

    public init(_ value: Seconds, leeway: Seconds = 0) {
        self.value = value
        self.leeway = leeway
    }

    public func verify(_ other: Seconds) -> Bool {
        return other + leeway >= value
    }
}
