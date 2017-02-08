import Node

public struct JWTIDClaim: EqualityClaim, StringBacked {
    public static var name = "jti"

    public let value: String

    public init(_ value: String) {
        self.value = value
    }
}
