import Foundation

public extension JWK {
    public enum PublicKeyUse: RawRepresentable, Codable {
        case signature
        case encryption
        case other(String)

        public var rawValue: String {
            switch self {
            case .signature:
                return "sig"
            case .encryption:
                return "enc"
            case .other(let value):
                return value
            }
        }

        public init(rawValue: String) {
            switch rawValue {
            case "sig":
                self = .signature
            case "enc":
                self = .encryption
            default:
                self = .other(rawValue)
            }
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let rawValue = try container.decode(String.self)
            self.init(rawValue: rawValue)
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(self.rawValue)
        }
    }
}
