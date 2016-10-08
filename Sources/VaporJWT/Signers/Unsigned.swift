import Core

public struct Unsigned: Signer {

    public let name = "none"

    public init() {}

    public func sign(_ message: Bytes) throws -> Bytes {
        return []
    }

    public func verifySignature(_ signature: Bytes,
                                message: Bytes) throws -> Bool {
        return true
    }
}
