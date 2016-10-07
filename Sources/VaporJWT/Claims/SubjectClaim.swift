import Node

public struct SubjectClaim: EqualityClaim, StringBacked {

    public static var name = "sub"

    public let value: String

    public init(_ value: String) {
        self.value = value
    }
}
