import Debugging

/// Errors that can be thrown while working with JWT.
public struct JWTError: Debuggable, Error {
    /// See `Debuggable`.
    public static var readableName = "JWT Error"

    /// See `Debuggable`.
    public var reason: String

    /// See `Debuggable`.
    public var identifier: String

    /// Create a new `JWTError`.
    public init(identifier: String, reason: String) {
        self.identifier = identifier
        self.reason = reason
    }
}
