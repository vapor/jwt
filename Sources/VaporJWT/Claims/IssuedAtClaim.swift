import Foundation
import Node

public struct IssuedAtClaim: DateBacked, EqualityClaim {

    public static var name = "iat"

    public let value: Date

    public init(_ value: Date) {
        self.value = value
    }
}
