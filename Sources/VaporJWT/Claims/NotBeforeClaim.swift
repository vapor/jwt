import Foundation
import Node

public struct NotBeforeClaim: SecondsWithLeewayClaim {
    public static var name = "nbf"

    public let leeway: Int
    public let value: Int

    public init(_ value: Int, leeway: Int = 0) {
        self.value = value
        self.leeway = leeway
    }

    public func verify(_ other: Int) -> Bool {
        return other + leeway >= value
    }
}
