import Foundation
import Node

public struct NotBeforeClaim: DateWithLeewayClaim {
    public static var name = "nbf"

    public let leeway: TimeInterval
    public let value: Date

    public init(_ value: Date = Date(), leeway: TimeInterval = 0) {
        self.value = value
        self.leeway = leeway
    }

    public func verify(_ other: Date) -> Bool {
        return other.addingTimeInterval(leeway) >= value
    }
}
