import CJWTKitCrypto
import struct Foundation.Data

extension JWTSigner {
    // MARK: RSA

    public static func rs256(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(EVP_sha256()),
            name: "RS256"
        ))
    }

    public static func rs384(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(EVP_sha384()),
            name: "RS384"
        ))
    }

    public static func rs512(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(EVP_sha512()),
            name: "RS512"
        ))
    }
}

public final class RSAKey: OpenSSLKey {
    public static func `public`<Data>(pem data: Data) throws -> RSAKey
        where Data: DataProtocol
    {
        let pkey = try self.load(pem: data) { bio in
            PEM_read_bio_PUBKEY(convert(bio), nil, nil, nil)
        }
        defer { EVP_PKEY_free(pkey) }

        guard let c = EVP_PKEY_get1_RSA(pkey) else {
            throw JWTError.signingAlgorithmFailure(RSAError.keyInitializationFailure)
        }
        return self.init(convert(c), .public)
    }

    public static func `private`<Data>(pem data: Data) throws -> RSAKey
        where Data: DataProtocol
    {
        let pkey = try self.load(pem: data) { bio in
            PEM_read_bio_PrivateKey(convert(bio), nil, nil, nil)
        }
        defer { EVP_PKEY_free(pkey) }

        guard let c = EVP_PKEY_get1_RSA(pkey) else {
            throw JWTError.signingAlgorithmFailure(RSAError.keyInitializationFailure)
        }
        return self.init(convert(c), .private)
    }
    
    public convenience init?(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) {
        func decode(_ string: String) -> [UInt8] {
            return [UInt8](string.utf8).base64URLDecodedBytes()
        }
        let n = decode(modulus)
        let e = decode(exponent)
        let d = privateExponent.flatMap { decode($0) }
        
        guard let rsa = RSA_new() else {
            return nil
        }
        
        jwtkit_RSA_set0_key(
            rsa,
            BN_bin2bn(n, numericCast(n.count), nil),
            BN_bin2bn(e, numericCast(e.count), nil),
            d.flatMap { BN_bin2bn($0, numericCast($0.count), nil) }
        )
        self.init(convert(rsa), d == nil ? .public : .private)
    }

    enum KeyType {
        case `public`, `private`
    }

    let type: KeyType
    let c: OpaquePointer

    init(_ c: OpaquePointer, _ type: KeyType) {
        self.type = type
        self.c = c
    }

    deinit {
        RSA_free(convert(self.c))
    }
}

// MARK: Private

private enum RSAError: Error {
    case privateKeyRequired
    case signFailure
    case keyInitializationFailure
}

private struct RSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: RSAKey
    let algorithm: OpaquePointer
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        guard case .private = self.key.type else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }
        var signatureLength: UInt32 = 0
        var signature = [UInt8](
            repeating: 0,
            count: Int(RSA_size(convert(key.c)))
        )

        let digest = try self.digest(plaintext)
        guard RSA_sign(
            EVP_MD_type(convert(self.algorithm)),
            digest,
            numericCast(digest.count),
            &signature,
            &signatureLength,
            convert(self.key.c)
        ) == 1 else {
            throw JWTError.signingAlgorithmFailure(RSAError.signFailure)
        }

        return .init(signature[0..<numericCast(signatureLength)])
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        let signature = signature.copyBytes()
        return RSA_verify(
            EVP_MD_type(convert(self.algorithm)),
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            convert(self.key.c)
        ) == 1
    }
}
