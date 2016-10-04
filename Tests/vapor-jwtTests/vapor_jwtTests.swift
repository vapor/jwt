@testable import vapor_jwt
import CLibreSSL
import Core
import Foundation
import Hash
import HMAC
import JSON
import XCTest

enum JWTError: Error {
    case couldNotGenerateKey
    case incorrectNumberOfSegments
    case missingAlgorithm
    case notBase64Encoded
    case unsupportedAlgorithm
}

extension JSON {

    init(base64Encoded: String) throws {
        guard let data = Data(base64Encoded: base64Encoded) else {
            throw JWTError.notBase64Encoded
        }

        try self.init(bytes: try data.makeBytes())
    }
    
    func base64String() throws -> String {
        return try makeBytes().base64String
    }
}

struct JWToken {

    enum Header: String {
        case algorithm = "alg"
        case type = "typ"
    }

    private let algorithmHeaderValue: String
    let header: JSON
    let payload: JSON
    let signature: String

    init(payload: JSON, algorithm: Algorithm) throws {
        header = JSON([Header.algorithm.rawValue: .string(algorithm.headerValue),
                       Header.type.rawValue: "JWT"])
        self.algorithmHeaderValue = algorithm.headerValue
        self.payload = payload
        let encodedHeaderAndPayload = "\(try header.base64String()).\(try payload.base64String())"
        signature = try algorithm.encrypt(encodedHeaderAndPayload)
    }

    init(token: String) throws {
        let segments = token.components(separatedBy: ".")
        guard segments.count == 3 else {
            throw JWTError.incorrectNumberOfSegments
        }
        header = try JSON(base64Encoded: segments[0])
        guard let alg = header.object?[Header.algorithm.rawValue]?.string else {
            throw JWTError.missingAlgorithm
        }
        algorithmHeaderValue = alg
        payload = try JSON(base64Encoded: segments[1])
        signature = segments[2]
    }

    func tokenString() throws -> String {
        return "\(try header.base64String()).\(try payload.base64String()).\(signature)"
    }

    func verifySignature(key: String) throws -> Bool {
        let algorithm = try Algorithm(algorithmHeaderValue, key: key)

        let encodedHeaderAndPayload = "\(try header.base64String()).\(try payload.base64String())"

        return try algorithm.verifySignature(signature, message: encodedHeaderAndPayload)
    }
}

func newECKeyPair(_ hashSize: HashSize) throws -> OpaquePointer {
    guard
        let ecKey = EC_KEY_new_by_curve_name(hashSize.curve),
        let privateBytes = try Data(base64Encoded: hashSize.key)?.makeBytes() else {
            throw JWTError.couldNotGenerateKey
    }
    var privateNum = BIGNUM()

    // Set private key

    BN_init(&privateNum)
    BN_bin2bn(privateBytes, Int32(privateBytes.count), &privateNum)
    EC_KEY_set_private_key(ecKey, &privateNum)

    // Derive public key

    let context = BN_CTX_new()
    BN_CTX_start(context)

    let group = EC_KEY_get0_group(ecKey)
    let publicKey = EC_POINT_new(group)
    EC_POINT_mul(group, publicKey, &privateNum, nil, nil, context)
    EC_KEY_set_public_key(ecKey, publicKey)

    // Release resources

    EC_POINT_free(publicKey)
    BN_CTX_end(context)
    BN_CTX_free(context)
    BN_clear_free(&privateNum)
    
    return ecKey
}

func newECPublicKey(_ hashSize: HashSize) throws -> OpaquePointer {
    guard let publicBytes = try Data(base64Encoded: hashSize.key)?.makeBytes() else {
        throw JWTError.couldNotGenerateKey
    }

    var ecKey = EC_KEY_new_by_curve_name(hashSize.curve)
    var publicBytesPointer: UnsafePointer? = UnsafePointer<UInt8>(publicBytes)

    if let ecKey = o2i_ECPublicKey(&ecKey, &publicBytesPointer, publicBytes.count) {
        return ecKey
    } else {
        throw JWTError.couldNotGenerateKey
    }
}

enum HashSize {
    case _256(String)
    case _384(String)
    case _512(String)
}

extension HashSize {

    init(_ string: String, key: String) throws {
        switch string {
        case "256": self = ._256(key)
        case "384": self = ._384(key)
        case "512": self = ._512(key)
        default:
            throw JWTError.unsupportedAlgorithm
        }
    }

    var curve: Int32 {
        switch self {
        case ._256: return NID_secp256k1
        case ._384: return NID_secp384r1
        case ._512: return NID_secp521r1
        }
    }

    var key: String {
        switch self {
        case ._256(let key), ._384(let key), ._512(let key):
            return key
        }
    }

    var shaHashMethod: Hash.Method {
        switch self {
        case ._256: return .sha256
        case ._384: return .sha384
        case ._512: return .sha512
        }
    }

    var shaHMACMethod: HMAC.Method {
        switch self {
        case ._256: return .sha256
        case ._384: return .sha384
        case ._512: return .sha512
        }
    }

    var string: String {
        switch self {
        case ._256: return "256"
        case ._384: return "384"
        case ._512: return "512"
        }
    }
}

enum Algorithm {
    case none
    case es(HashSize)
    case hs(HashSize)
//    case rs(HashSize)
}

extension Algorithm {

    init(_ string: String, key: String) throws {
        guard string != "none" else {
            self = .none
            return
        }

        let hashSizeRange = string.index(string.startIndex, offsetBy: 2)..<string.endIndex
        let hashSize = try HashSize(string[hashSizeRange], key: key)

        switch string.substring(to: string.index(string.startIndex, offsetBy: 2)).lowercased() {
        case "es":
            self = .es(hashSize)
        case "hs":
            self = .hs(hashSize)
        default:
            throw JWTError.unsupportedAlgorithm
        }
    }

    var headerValue: String {
        switch self {
        case .none: return "none"
        case .hs(let hashSize):
            return "HS" + hashSize.string
        case .es(let hashSize):
            return "ES" + hashSize.string
        }
    }

    func encrypt(_ message: String) throws -> String {
        switch self {
        case .hs(let hashSize):
            return try HMAC(hashSize.shaHMACMethod, message.bytes)
                .authenticate(key: hashSize.key.bytes).base64String
        case .es(let hashSize):
            var digest = try Hash(hashSize.shaHashMethod, message.bytes).hash()
            let ecKey = try newECKeyPair(hashSize)

            guard let sig = ECDSA_do_sign(&digest, Int32(digest.count), ecKey) else {
                throw JWTError.couldNotGenerateKey
            }

            var byte: UnsafeMutablePointer<UInt8>? = nil
            let derLength = i2d_ECDSA_SIG(sig, &byte)

            guard let byte2 = byte, derLength > 0 else {
                throw JWTError.couldNotGenerateKey
            }

            var bytes: [UInt8] = [UInt8](repeating: 0, count: Int(derLength))

            for b in 0..<Int(derLength) {
                bytes[b] = byte2[b]
            }

            return bytes.base64String
        default:
            return ""
        }
    }

    func verifySignature(_ signature: String, message: String) throws -> Bool {
        switch self {
        case .none: return true
        case .hs:
            return try encrypt(message) == signature
        case .es(let hashSize):
            guard let der = Data(base64Encoded: signature) else {
                throw JWTError.notBase64Encoded
            }
            let derBytes = try der.makeBytes()
            var derBytesPointer: UnsafePointer? = UnsafePointer(derBytes)
            let signature = d2i_ECDSA_SIG(nil, &derBytesPointer, derBytes.count)
            let digest = try Hash(hashSize.shaHashMethod, message.bytes).hash()
            let ecKey = try newECPublicKey(hashSize)
            let verified = ECDSA_do_verify(digest, Int32(digest.count), signature, ecKey)
            return verified == 1
        }
    }
}

class vapor_jwtTests: XCTestCase {

    let message = JSON(["a": .string("b")])

    func testEncodeWithoutEncryption() {
        do {
            let token = try JWToken(payload: message, algorithm: .none)
            XCTAssertEqual(try token.tokenString(),
                           "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJhIjoiYiJ9.")
            XCTAssertTrue(try token.verifySignature(key: ""))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithHS256Encryption() {
        do {
            let token = try JWToken(payload: message, algorithm: .hs(._256("secret")))
            XCTAssertEqual(try token.tokenString(),
                           "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8=")
            XCTAssertTrue(try token.verifySignature(key: "secret"))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithHS384Encryption() {
        do {
            let token = try JWToken(payload: message, algorithm: .hs(._384("secret")))
            XCTAssertEqual(try token.tokenString(),
                           "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.TgJIRKof/BR1EVkcRXV/xt8IxffTwQKUyOZIUUWFrC6sFAGIDe1HZksCbSIhKyoD")
            XCTAssertTrue(try token.verifySignature(key: "secret"))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithHS512Encryption() {
        do {
            let token = try JWToken(payload: message, algorithm: .hs(._512("secret")))
            XCTAssertEqual(try token.tokenString(),
                           "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.NEvauwy77uvgEvKOlGLmLJJEseamUKhAAPaGaWlD5P5qLHkLiHC9eQOy4YwR+L3BjNN1lumBhg8eEHus23CflQ==")
            XCTAssertTrue(try token.verifySignature(key: "secret"))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithES256Encryption() {
        let privateKey = "AL3BRa7llckPgUw3Si2KCy1kRUZJ/pxJ29nlr86xlm0="
        let publicKey = "BPtT5aOJu133UmfZNr6J0xYifrtknN0sk0VbuB/xqdQHCFpzpWmm8c9HnesXRvu21o37MkzkO6hKxGFNzO73UGc="

        do {
            let token = try JWToken(payload: message, algorithm: .es(._256(privateKey)))
            XCTAssertTrue(try token.verifySignature(key: publicKey))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithES384Encryption() {
        let privateKey = "BVjgIwqB1PeIv0YP3ZeQ7CTqW+9+yJ7Y/jXPr1tfrb3ne5TQNMU2rOxYtf6M6IN9"
        let publicKey = "BAV9NUl1v488eXcDhStPTK57Dg4Cm+XCjmFGD1IXjkF+LJNG963oUkYjV1xxNQgxJka7tsXjadei25PdZatX3GS6KivPiNu1YdeSpXxr5d73sdLU/rq/OgDLUUcic77g3A=="

        do {
            let token = try JWToken(payload: message, algorithm: .es(._384(privateKey)))
            XCTAssertTrue(try token.verifySignature(key: publicKey))
        } catch {
            XCTFail()
        }
    }

    func testEncodeWithES512Encryption() {
        let privateKey = "AdcqLUGC+4OlxqGRJkz6++BD9tfDtNM1NvTQh7M0stzvMMvcaNio87YUD6Gaks0eS9Krvs1Bkqo/T7k9DW8Eyoec"
        let publicKey = "BACJKkoouMqhbgZtTSyQJHECDf/V2ArN7VwuaIUIKsx/OFiF79ccrzCSZ1MrGOmQgPAez6pqjUIjhwoHr5tRH65BggEUhC7SNvRvfMeElOrZNac9uTVnfGJ1DywnL+JtD49ytuD9GjifUPHJi4RcN36RHLXyBpF0u1+RRFbKCNhnJ132Pw=="

        do {
            let token = try JWToken(payload: message, algorithm: .es(._512(privateKey)))
            XCTAssertTrue(try token.verifySignature(key: publicKey))
        } catch {
            XCTFail()
        }
    }

    func testDecode() {
        XCTAssertEqual(try JSON(base64Encoded: "eyJhIjoiYiJ9"), message)
    }

    func testNotBase64Encoded() {
        XCTAssertThrowsError(try JSON(base64Encoded: "0")) {
            guard let error = $0 as? JWTError, case .notBase64Encoded = error else {
                XCTFail()
                return
            }
            return
        }
    }

    func testHeaderKeys() {
        let all: [Algorithm] = [
            .none,
            .hs(._256("")),
            .hs(._384("")),
            .hs(._512("")),
            .es(._256("")),
            .es(._384("")),
            .es(._512(""))
        ]
        XCTAssertEqual(all.map { $0.headerValue }, [
            "none",
            "HS256",
            "HS384",
            "HS512",
            "ES256",
            "ES384",
            "ES512"
        ])
    }
}
