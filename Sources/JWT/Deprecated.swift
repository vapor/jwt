extension ExpirationClaim {
    /// Deprecated.
    @available(*, deprecated, renamed: "verifyNotExpired")
    public func verify() throws {
        try verifyNotExpired()
    }
}

extension NotBeforeClaim {
    /// Deprecated.
    @available(*, deprecated, renamed: "verifyNotBefore")
    public func verify() throws {
        try verifyNotBefore()
    }
}
