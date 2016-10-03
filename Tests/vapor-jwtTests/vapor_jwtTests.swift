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

enum Algorithm {
    case none
    case hs256(String)
    case hs384(String)
    case hs512(String)
//    case rs256(String)
//    case rs384(String)
//    case rs512(String)
    case es256(String)
//    case es384(String)
//    case es512(String)
}

//let privateKeyBytes: Bytes = [0x8e,0xbc,0xd1,0x89,0x6b,0x3a,0x83,0x47,0x46,0x1d,0x24,0x57,0xaa,0x11,0xe2,0xd0,0xe4,0x1e,0x8e,0x10,0xf3,0xdb,0xf4,0xe9,0x49,0xde,0x25,0xa9,0xe4,0x0d,0x2c,0xa6]
let privateKey = "jrzRiWs6g0dGHSRXqhHi0OQejhDz2/TpSd4lqeQNLKY="

func newKeyPair(privateBase64Key: String) throws -> OpaquePointer {
    guard
        let ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
        let privateBytes = try Data(base64Encoded: privateBase64Key)?.makeBytes(),
        privateBytes.count == 32 else {
            throw JWTError.couldNotGenerateKey
    }
    var privateNum = BIGNUM()

    // Set private key

    BN_init(&privateNum)
    BN_bin2bn(privateBytes, 32, &privateNum)
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

extension Algorithm {

    func encrypt(_ string: String) throws -> String {

        if case .es256(let privateKey) = self {
            var digest = try Hash(.sha256, string.bytes).hash()

            let ecKey = try newKeyPair(privateBase64Key: privateKey)

            let digestLength = Int32(digest.count)

            guard let sig = ECDSA_do_sign(&digest, digestLength, ecKey) else {
                throw JWTError.couldNotGenerateKey
            }

            guard ECDSA_do_verify(&digest, digestLength, sig, ecKey) == 1 else {
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
        } else if let method = method, let signKey = signKey {
            return try HMAC(method, string.bytes).authenticate(key: signKey.bytes).base64String
        }

        return ""
    }

    var signKey: String? {
        switch self {
        case .hs256(let key), .hs384(let key), .hs512(let key):
            return key
        default:
            return nil
        }
    }

    var headerValue: String {
        switch self {
        case .none: return "none"
        case .hs256: return "HS256"
        case .hs384: return "HS384"
        case .hs512: return "HS512"
//        case .rs256: return "RS256"
//        case .rs384: return "RS384"
//        case .rs512: return "RS512"
        case .es256: return "ES256"
//        case .es384: return "ES384"
//        case .es512: return "ES512"
        }
    }

    private var method: HMAC.Method? {
        switch self {
        case .hs256: return .sha256
        case .hs384: return .sha384
        case .hs512: return .sha512
//        case .rs256: return
//        case .rs384: return
//        case .rs512: return
        default: return nil
        }
    }
}

extension Algorithm {
    static var all: [Algorithm] {
        return [
            .hs256(""),
            .hs384(""),
            .hs512(""),
//            .rs256(""),
//            .rs384(""),
//            .rs512(""),
            .es256(""),
//            .es384(""),
//            .es512("")

        ]
    }
}

class vapor_jwtTests: XCTestCase {

    func testEncode() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .none),
                       "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJhIjoiYiJ9.")
    }

    func testEncodeWithHS256Encryption() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .hs256("secret")),
                       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67/QGs52AzC8Ru8=")
    }

    func testEncodeWithHS384Encryption() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .hs384("secret")),
                       "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.TgJIRKof/BR1EVkcRXV/xt8IxffTwQKUyOZIUUWFrC6sFAGIDe1HZksCbSIhKyoD")
    }

    func testEncodeWithHS512Encryption() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .hs512("secret")),
                       "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.NEvauwy77uvgEvKOlGLmLJJEseamUKhAAPaGaWlD5P5qLHkLiHC9eQOy4YwR+L3BjNN1lumBhg8eEHus23CflQ==")
    }

    func testEncodeWithES256Encryption() {
        XCTAssertEqual(try encode(JSON(["a": .string("b")]), with: .es256(privateKey)),
                       "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.MEUCIElt+2fI1t5Lj/EcVho2JUSpw0Pl64GdNOpKXVzEeWZcAiEAnmZ0uCdOVdKdVnAqfBsbiETNiToWfgZNYaSsVL7wibA=")
    }

    func testDecode() {
        XCTAssertEqual(try decode("eyJhIjoiYiJ9"), JSON(["a": .string("b")]))
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
        XCTAssertEqual(
            Algorithm.all.map { $0.headerValue }, [
                "HS256",
                "HS384",
                "HS512",
//                "RS256",
//                "RS384",
//                "RS512",
                "ES256",
//                "ES384",
//                "ES512"
            ])
    }
}
