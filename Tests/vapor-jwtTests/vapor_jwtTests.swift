@testable import vapor_jwt
import CLibreSSL
import Core
import Foundation
import Hash
import HMAC
import JSON
import XCTest

enum Header: String {
    case algorithm = "alg"
    case type = "typ"
}

enum JWTError: Error {
    case notBase64Encoded
    case couldNotGenerateKey
}

extension JSON {
    func base64String() throws -> String {
        return try makeBytes().base64String
    }
}

func encode(_ payload: JSON, with algorithm: Algorithm) throws -> String {
    let header = JSON([Header.algorithm.rawValue: .string(algorithm.headerValue),
                       Header.type.rawValue: "JWT"])

    let encodedHeaderAndPayload = "\(try header.base64String()).\(try payload.base64String())"
    let signature = try algorithm.encrypt(encodedHeaderAndPayload)

    return "\(encodedHeaderAndPayload).\(signature)"
}

func decode(_ jwt: String) throws -> JSON {
    guard let data = Data(base64Encoded: jwt) else {
        throw JWTError.notBase64Encoded
    }

    return try JSON(bytes: try data.makeBytes())
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

    // Convert public key to base64 string

    EC_KEY_set_conv_form(ecKey, POINT_CONVERSION_UNCOMPRESSED)

    let pub_len = i2o_ECPublicKey(ecKey, nil)
    var pub: UnsafeMutablePointer<UInt8>? = nil

    guard i2o_ECPublicKey(ecKey, &pub) == pub_len else {
        throw JWTError.couldNotGenerateKey
    }

    if let pub = pub {
        var publicBytes = Bytes(repeating: 0, count: Int(pub_len))
        for i in 0..<Int(pub_len) {
            publicBytes[i] = Byte(pub[i])
        }
        let publicData = Data(bytes: publicBytes)
        print("public key: \(publicData.base64String)")
    } else {
        throw JWTError.couldNotGenerateKey
    }

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
    case hs(HashSize)
//    case rs(HashSize)
    case es(HashSize)
}

extension Algorithm {

    func encrypt(_ string: String) throws -> String {
        switch self {
        case .hs(let hashSize):
            return try HMAC(hashSize.shaHMACMethod, string.bytes).authenticate(key: hashSize.key.bytes).base64String
        case .es(let hashSize):
            var digest = try Hash(hashSize.shaHashMethod, string.bytes).hash()
            let digestLength = Int32(digest.count)

            let ecKey = try newECKeyPair(hashSize)

            guard let sig = ECDSA_do_sign(&digest, digestLength, ecKey) else {
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

    var headerValue: String {
        switch self {
        case .none: return "none"
        case .hs(let hashSize):
            return "HS" + hashSize.string
        case .es(let hashSize):
            return "ES" + hashSize.string
        }
    }
}

class vapor_jwtTests: XCTestCase {

    let message = JSON(["a": .string("b")])

    func testEncode() {
        XCTAssertEqual(try encode(message, with: .none),
                       "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJhIjoiYiJ9.")
    }

    func testEncodeWithHS256Encryption() {
        XCTAssertEqual(try encode(message, with: .hs(._256("secret"))),
                       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8=")
    }

    func testEncodeWithHS384Encryption() {
        XCTAssertEqual(try encode(message, with: .hs(._384("secret"))),
                       "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.TgJIRKof/BR1EVkcRXV/xt8IxffTwQKUyOZIUUWFrC6sFAGIDe1HZksCbSIhKyoD")
    }

    func testEncodeWithHS512Encryption() {
        XCTAssertEqual(try encode(message, with: .hs(._512("secret"))),
                       "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.NEvauwy77uvgEvKOlGLmLJJEseamUKhAAPaGaWlD5P5qLHkLiHC9eQOy4YwR+L3BjNN1lumBhg8eEHus23CflQ==")
    }

    func testEncodeWithES256Encryption() {
        let privateKey = "AL3BRa7llckPgUw3Si2KCy1kRUZJ/pxJ29nlr86xlm0="
        let publicKey = "BPtT5aOJu133UmfZNr6J0xYifrtknN0sk0VbuB/xqdQHCFpzpWmm8c9HnesXRvu21o37MkzkO6hKxGFNzO73UGc="

        let token = try! encode(message, with: .es(._256(privateKey)))
        let segments = token.components(separatedBy: ".")

        XCTAssertEqual(segments.count, 3)
        let derBytes = try! Data(base64Encoded: segments[2])!.makeBytes()
        var derBytesPointer: UnsafePointer? = UnsafePointer(derBytes)

        let signature = d2i_ECDSA_SIG(nil, &derBytesPointer, derBytes.count)

        let digest = try! Hash(.sha256, "\(segments[0]).\(segments[1])".bytes).hash()
        let ecKey = try! newECPublicKey(._256(publicKey))
        let verified = ECDSA_do_verify(digest, Int32(digest.count), signature, ecKey)

        XCTAssertEqual(verified, 1)
    }

    func testEncodeWithES384Encryption() {
        let privateKey = "BVjgIwqB1PeIv0YP3ZeQ7CTqW+9+yJ7Y/jXPr1tfrb3ne5TQNMU2rOxYtf6M6IN9"
        let publicKey = "BAV9NUl1v488eXcDhStPTK57Dg4Cm+XCjmFGD1IXjkF+LJNG963oUkYjV1xxNQgxJka7tsXjadei25PdZatX3GS6KivPiNu1YdeSpXxr5d73sdLU/rq/OgDLUUcic77g3A=="

        let token = try! encode(message, with: .es(._384(privateKey)))
        let segments = token.components(separatedBy: ".")

        XCTAssertEqual(segments.count, 3)
        let derBytes = try! Data(base64Encoded: segments[2])!.makeBytes()
        var derBytesPointer: UnsafePointer? = UnsafePointer(derBytes)

        let signature = d2i_ECDSA_SIG(nil, &derBytesPointer, derBytes.count)

        let digest = try! Hash(.sha384, "\(segments[0]).\(segments[1])".bytes).hash()
        let ecKey = try! newECPublicKey(._384(publicKey))
        let verified = ECDSA_do_verify(digest, Int32(digest.count), signature, ecKey)

        XCTAssertEqual(verified, 1)
    }

    func testEncodeWithES512Encryption() {
        let privateKey = "AdcqLUGC+4OlxqGRJkz6++BD9tfDtNM1NvTQh7M0stzvMMvcaNio87YUD6Gaks0eS9Krvs1Bkqo/T7k9DW8Eyoec"
        let publicKey = "BACJKkoouMqhbgZtTSyQJHECDf/V2ArN7VwuaIUIKsx/OFiF79ccrzCSZ1MrGOmQgPAez6pqjUIjhwoHr5tRH65BggEUhC7SNvRvfMeElOrZNac9uTVnfGJ1DywnL+JtD49ytuD9GjifUPHJi4RcN36RHLXyBpF0u1+RRFbKCNhnJ132Pw=="

        let token = try! encode(message, with: .es(._512(privateKey)))
        let segments = token.components(separatedBy: ".")

        XCTAssertEqual(segments.count, 3)
        let derBytes = try! Data(base64Encoded: segments[2])!.makeBytes()
        var derBytesPointer: UnsafePointer? = UnsafePointer(derBytes)

        let signature = d2i_ECDSA_SIG(nil, &derBytesPointer, derBytes.count)

        let digest = try! Hash(.sha512, "\(segments[0]).\(segments[1])".bytes).hash()
        let ecKey = try! newECPublicKey(._512(publicKey))
        let verified = ECDSA_do_verify(digest, Int32(digest.count), signature, ecKey)

        XCTAssertEqual(verified, 1)
    }

    func testDecode() {
        XCTAssertEqual(try decode("eyJhIjoiYiJ9"), message)
    }

    func testNotBase64Encoded() {
        XCTAssertThrowsError(try decode("0")) {
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
