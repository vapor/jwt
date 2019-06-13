public struct JWTMessage: ContiguousBytes, CustomStringConvertible, Hashable, Sequence {
    var header: [UInt8]
    var payload: [UInt8]
    var signature: [UInt8]
    
    public var description: String {
        return String(decoding: self.bytes, as: UTF8.self)
    }
    
    public var bytes: [UInt8] {
        return self.header + [.period] + self.payload + [.period] + self.signature
    }
    
    init(bytes: [UInt8]) throws {
        let parts = bytes.split(separator: .period)
        guard parts.count == 3 else {
            throw JWTError(identifier: "format", reason: "Invalid JWT format")
        }
        self.init(header: parts[0], payload: parts[1], signature: parts[2])
    }
    
    init<Header, Payload, Signature>(
        header: Header, payload: Payload, signature: Signature
    )
        where Header: DataProtocol, Payload: DataProtocol, Signature: DataProtocol
    {
        self.header = header.copyBytes()
        self.payload = payload.copyBytes()
        self.signature = signature.copyBytes()
    }
    
    public func makeIterator() -> Array<UInt8>.Iterator {
        return self.bytes.makeIterator()
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}
