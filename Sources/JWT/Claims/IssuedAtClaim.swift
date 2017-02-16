import Foundation
import Node

public struct IssuedAtClaim: SecondsBacked, EqualityClaim {
    public static var name = "iat"

    public let value: Seconds

    public init(seconds: Seconds) {
        self.value = seconds
    }
}
