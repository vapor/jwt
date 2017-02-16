import Node

public struct SubjectClaim: EqualityClaim, StringBacked {
    public static var name = "sub"

    public let value: String

    public init(string: String) {
        self.value = string
    }
}
