import struct Foundation.Data

extension DataProtocol {
    func base64URLDecodedBytes() -> [UInt8] {
        return Data(base64Encoded: Data(self.copyBytes()).base64URLUnescaped())?.copyBytes() ?? []
    }

    func base64URLEncodedBytes() -> [UInt8] {
        return Data(self.copyBytes()).base64EncodedData().base64URLEscaped().copyBytes()
    }
}

/// MARK: Data Escape
private extension Data {
    /// Converts base64-url encoded data to a base64 encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    mutating func base64URLUnescape() {
        for (i, byte) in self.enumerated() {
            switch byte {
            case 0x2D: self[self.index(self.startIndex, offsetBy: i)] = 0x2B
            case 0x5F: self[self.index(self.startIndex, offsetBy: i)] = 0x2F
            default: break
            }
        }
        /// https://stackoverflow.com/questions/43499651/decode-base64url-to-base64-swift
        let padding = count % 4
        if padding > 0 {
            self += Data(repeating: 0x3D, count: 4 - count % 4)
        }
    }

    /// Converts base64 encoded data to a base64-url encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    mutating func base64URLEscape() {
        for (i, byte) in enumerated() {
            switch byte {
            case 0x2B: self[self.index(self.startIndex, offsetBy: i)] = 0x2D
            case 0x2F: self[self.index(self.startIndex, offsetBy: i)] = 0x5F
            default: break
            }
        }
        self = split(separator: 0x3D).first ?? .init()
    }

    /// Converts base64-url encoded data to a base64 encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    func base64URLUnescaped() -> Self {
        var data = self
        data.base64URLUnescape()
        return data
    }

    /// Converts base64 encoded data to a base64-url encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    func base64URLEscaped() -> Self {
        var data = self
        data.base64URLEscape()
        return data
    }
}
