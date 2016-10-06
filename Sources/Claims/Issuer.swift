import Node

public struct Issuer: EqualityClaim, StringBacked {

    public static var name = "iss"

    public let value: String

    public init(_ value: String) {
        self.value = value
    }
}
