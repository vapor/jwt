import Node

public struct JWTID: EqualityClaim, StringBacked {

    public static var name = "jti"

    public let value: String

    public init(_ value: String) {
        self.value = value
    }
}
