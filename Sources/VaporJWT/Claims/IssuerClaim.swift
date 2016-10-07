import Node

public struct IssuerClaim: EqualityClaim, StringBacked {

    public static var name = "iss"

    public let value: String

    public init(_ value: String) {
        self.value = value
    }
}
