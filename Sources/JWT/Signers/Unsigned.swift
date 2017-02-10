import Core

public struct Unsigned: Signer {
    public let name = "none"

    public init() {}

    public func sign(message: Bytes) throws -> Bytes {
        return []
    }

    public func verify(signature: Bytes, message: Bytes) throws {
        // always pass
    }
}
