import Foundation
import Node

public struct IssuedAtClaim: SecondsBacked, EqualityClaim {
    public static var name = "iat"

    public let value: Seconds

    public init(_ value: Seconds) {
        self.value = value
    }
}
