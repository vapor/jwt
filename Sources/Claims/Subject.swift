import Node

public struct Subject: EqualityClaim, StringBacked {

    public static var name = "sub"

    public let value: String

    public init(_ value: String) {
        self.value = value
    }
}
