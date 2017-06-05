import Core

/// Some data structure capable of signing
/// an array of bytes and later verifying
/// a signature against a raw array of bytes
public protocol Signer {
    var name: String { get }
    func sign(message: Bytes) throws -> Bytes
    func verify(signature: Bytes, message: Bytes) throws
}

extension Signer {
    public var name: String {
        return String(describing: Self.self)
    }

    public func sign(message convertible: BytesConvertible) throws -> Bytes {
        let bytes = try convertible.makeBytes()
        return try sign(message: bytes)
    }

    public func verify(signature: BytesConvertible, message: BytesConvertible) throws {
        let signatureBytes = try signature.makeBytes()
        let messageBytes = try message.makeBytes()
        return try verify(
            signature: signatureBytes,
            message: messageBytes
        )
    }
}
