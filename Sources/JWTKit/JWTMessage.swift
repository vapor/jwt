public struct JWTMessage {
    let bytes: [UInt8]
    
    init(bytes: [UInt8]) {
        self.bytes = bytes
    }
}
