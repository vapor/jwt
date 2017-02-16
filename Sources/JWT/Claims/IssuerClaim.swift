import Node

public struct IssuerClaim: EqualityClaim, StringBacked {
    public static var name = "iss"

    public let value: String

    public init(string: String) {
        self.value = string
    }
}
