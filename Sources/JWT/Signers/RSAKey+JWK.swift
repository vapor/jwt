import Foundation
import CTLS

public extension RSAKey {

    /**
        - parameter n: Base64 URL encoded string representing the `modulus` of the RSA Key.
        - parameter e: Base64 URL encoded string representing the `public exponent` of the RSA Key.
        - parameter d: Base64 URL encoded string representing the `private exponent` of the RSA Key.
     */
    public init(n: String, e: String, d: String? = nil) throws {

        func parseBignum(_ s: String) -> UnsafeMutablePointer<BIGNUM> {
            return s.makeBytes().base64URLDecoded.withUnsafeBufferPointer { p in
                return BN_bin2bn(p.baseAddress, Int32(p.count), nil)
            }
        }

        guard let rsa = RSA_new() else {
            throw JWTError.createKey
        }

        rsa.pointee.n = parseBignum(n)
        rsa.pointee.e = parseBignum(e)

        if let d = d {
            rsa.pointee.d = parseBignum(d)
            self = .private(rsa)
        } else {
            self = .public(rsa)
        }
    }
}
