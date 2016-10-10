import Foundation
import Node

public struct ExpirationTimeClaim: DateWithLeewayClaim {
    public static var name = "exp"

    public let leeway: TimeInterval
    public let value: Date

    public init(_ value: Date = Date(), leeway: TimeInterval = 0) {
        self.value = value
        self.leeway = leeway
    }

    public func verify(_ other: Date) -> Bool {
        return other <= value.addingTimeInterval(leeway)
    }
}
