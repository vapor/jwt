/// Encodes and decodes bytes using the
/// Base64 encoding
///
/// https://en.wikipedia.org/wiki/Base64

final class Base64Encoder {
    /// Static shared instance
    static let shared = Base64Encoder.regular
    
    /// Standard Base64Encoder
    static var regular: Base64Encoder {
        return Base64Encoder()
    }
    
    // Base64URLEncoder
    // - note: uses hyphens and underscores
    //         in place of plus and forwardSlash
    static var url: Base64Encoder {
        let encodeMap: Base64Encoder.ByteMap = { byte in
            switch byte {
            case 62:
                return 0x2D
            case 63:
                return 0x5F
            default:
                return nil
            }
        }
        
        let decodeMap: Base64Encoder.ByteMap = { byte in
            switch byte {
            case 0x2D:
                return 62
            case 0x5F:
                return 63
            default:
                return nil
            }
        }
        
        return Base64Encoder(
            padding: nil,
            encodeMap: encodeMap,
            decodeMap: decodeMap
        )
    }
    
    /// Maps binary format to base64 encoding
    static fileprivate let encodingTable: [UInt8: UInt8] = [
         0: 0x41,     1: 0x42,     2: 0x43,     3: 0x44,
         4: 0x45,     5: 0x46,     6: 0x47,     7: 0x48,
         8: 0x49,     9: 0x4A,    10: 0x4B,    11: 0x4C,
        12: 0x4D,    13: 0x4E,    14: 0x4F,    15: 0x50,
        16: 0x51,    17: 0x52,    18: 0x53,    19: 0x54,
        20: 0x55,    21: 0x56,    22: 0x57,    23: 0x58,
        24: 0x59,    25: 0x5A,    26: 0x61,    27: 0x62,
        28: 0x63,    29: 0x64,    30: 0x65,    31: 0x66,
        32: 0x67,    33: 0x68,    34: 0x69,    35: 0x6A,
        36: 0x6B,    37: 0x6C,    38: 0x6D,    39: 0x6E,
        40: 0x6F,    41: 0x70,    42: 0x71,    43: 0x72,
        44: 0x73,    45: 0x74,    46: 0x75,    47: 0x76,
        48: 0x77,    49: 0x78,    50: 0x79,    51: 0x7A,
        52: 0x30,    53: 0x31,    54: 0x32,    55: 0x33,
        56: 0x34,    57: 0x35,    58: 0x36,    59: 0x37,
        60: 0x38,    61: 0x39,    62: .plus,   63: .forwardSlash
    ]
    
    /// Maps base64 encoding into binary format
    static fileprivate let decodingTable: [UInt8: UInt8] = [
        0x41: 0,    0x42: 1,    0x43: 2,    0x44: 3,
        0x45: 4,    0x46: 5,    0x47: 6,    0x48: 7,
        0x49: 8,    0x4A: 9,    0x4B: 10,   0x4C: 11,
        0x4D: 12,   0x4E: 13,   0x4F: 14,   0x50: 15,
        0x51: 16,   0x52: 17,   0x53: 18,   0x54: 19,
        0x55: 20,   0x56: 21,   0x57: 22,   0x58: 23,
        0x59: 24,   0x5A: 25,   0x61: 26,   0x62: 27,
        0x63: 28,   0x64: 29,   0x65: 30,   0x66: 31,
        0x67: 32,   0x68: 33,   0x69: 34,   0x6A: 35,
        0x6B: 36,   0x6C: 37,   0x6D: 38,   0x6E: 39,
        0x6F: 40,   0x70: 41,   0x71: 42,   0x72: 43,
        0x73: 44,   0x74: 45,   0x75: 46,   0x76: 47,
        0x77: 48,   0x78: 49,   0x79: 50,   0x7A: 51,
        0x30: 52,   0x31: 53,   0x32: 54,   0x33: 55,
        0x34: 56,   0x35: 57,   0x36: 58,   0x37: 59,
        0x38: 60,   0x39: 61,  .plus: 62,  .forwardSlash: 63
    ]
    
    /// Typealias for optionally mapping a byte
    fileprivate typealias ByteMap = (UInt8) -> UInt8?
    
    /// Byte to use for padding base64
    /// if nil, no padding will be used
    fileprivate let padding: UInt8?
    
    /// If set, bytes returned will have priority
    /// over the encoding table. Encoding table
    /// will be used as a fallback
    fileprivate let encodeMap: ByteMap?
    
    /// If set, bytes returned will have priority
    /// over the decoding table. Decoding table
    /// will be used as a fallback
    fileprivate let decodeMap: ByteMap?
    
    /// Creates a new Base64 encoder
    fileprivate init(
        padding: UInt8? = .equals,
        encodeMap: ByteMap? = nil,
        decodeMap: ByteMap? = nil
        ) {
        self.padding = padding
        self.encodeMap = encodeMap
        self.decodeMap = decodeMap
    }
    
    /// Encodes bytes into Base64 format
    func encode(_ bytes: [UInt8]) -> [UInt8] {
        if bytes.count == 0 {
            return []
        }
        
        let len = bytes.count
        var offset: Int = 0
        var c1: UInt8
        var c2: UInt8
        var result: [UInt8] = []
        
        while offset < len {
            c1 = bytes[offset] & 0xff
            offset += 1
            result.append(encode((c1 >> 2) & 0x3f))
            c1 = (c1 & 0x03) << 4
            if offset >= len {
                result.append(encode(c1 & 0x3f))
                if let padding = self.padding {
                    result.append(padding)
                    result.append(padding)
                }
                break
            }
            
            c2 = bytes[offset] & 0xff
            offset += 1
            c1 |= (c2 >> 4) & 0x0f
            result.append(encode(c1 & 0x3f))
            c1 = (c2 & 0x0f) << 2
            if offset >= len {
                result.append(encode(c1 & 0x3f))
                if let padding = self.padding {
                    result.append(padding)
                }
                break
            }
            
            c2 = bytes[offset] & 0xff
            offset += 1
            c1 |= (c2 >> 6) & 0x03
            result.append(encode(c1 & 0x3f))
            result.append(encode(c2 & 0x3f))
        }
        
        return result
    }
    
    /// Decodes bytes into binary format
    func decode(_ s: [UInt8]) -> [UInt8] {
        let maxolen = s.count
        
        var off: Int = 0
        var olen: Int = 0
        var result = [UInt8](repeating: 0, count: maxolen)
        
        var c1: UInt8
        var c2: UInt8
        var c3: UInt8
        var c4: UInt8
        var o: UInt8
        
        while off < s.count - 1 && olen < maxolen {
            c1 = decode(s[off])
            off += 1
            c2 = decode(s[off])
            off += 1
            if c1 == UInt8.max || c2 == UInt8.max {
                break
            }
            
            o = c1 << 2
            o |= (c2 & 0x30) >> 4
            result[olen] = o
            olen += 1
            if olen >= maxolen || off >= s.count {
                break
            }
            
            c3 = decode(s[off])
            off += 1
            if c3 == UInt8.max {
                break
            }
            
            o = (c2 & 0x0f) << 4
            o |= (c3 & 0x3c) >> 2
            result[olen] = o
            olen += 1
            if olen >= maxolen || off >= s.count {
                break
            }
            
            c4 = decode(s[off])
            off += 1
            if c4 == UInt8.max {
                break
            }
            o = (c3 & 0x03) << 6
            o |= c4
            result[olen] = o
            olen += 1
        }
        
        return Array(result[0..<olen])
    }
    
    // MARK: Private
    
    private func encode(_ x: UInt8) -> UInt8 {
        return encodeMap?(x)
            ?? Base64Encoder.encodingTable[x]
            ?? UInt8.max
    }
    
    private func decode(_ x: UInt8) -> UInt8 {
        return decodeMap?(x)
            ?? Base64Encoder.decodingTable[x]
            ?? UInt8.max
    }
}
