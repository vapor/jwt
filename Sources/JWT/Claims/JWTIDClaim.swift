import Node

public struct JWTIDClaim: EqualityClaim, StringBacked {
    public static var name = "jti"

    public let value: String

    public init(string: String) {
        self.value = string
    }
}
