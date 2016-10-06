public protocol Header {
    static var headerKey: String { get }
    var headerValue: String { get }
}

public struct Type: Header {
    public static let headerKey = "typ"
    public let headerValue = "JWT"
}

extension Algorithm: Header {
    public static let headerKey = "alg"

    public var headerValue: String {
        return name
    }
}
