import Foundation

/// Errors that can be thrown while working with JWT.
public struct JWTError: Error, LocalizedError {
    /// See `Debuggable`.
    public static var readableName = "JWT Error"

    /// See `Debuggable`.
    public var reason: String

    /// See `Debuggable`.
    public var identifier: String
    
    public var errorDescription: String? {
        return self.reason
    }

    /// Create a new `JWTError`.
    public init(identifier: String, reason: String) {
        self.identifier = identifier
        self.reason = reason
    }
}
