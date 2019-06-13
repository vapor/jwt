import CJWTKitOpenSSL
import struct Foundation.Data

extension JWTSigner {
    // MARK: RSA

    public static func rs256(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSAAlgorithm(
            key: key,
            algorithm: EVP_sha256(),
            jwtAlgorithmName: "RS256"
        ))
    }

    public static func rs384(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSAAlgorithm(
            key: key,
            algorithm: EVP_sha384(),
            jwtAlgorithmName: "RS384"
        ))
    }

    public static func rs512(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSAAlgorithm(
            key: key,
            algorithm: EVP_sha512(),
            jwtAlgorithmName: "RS512"
        ))
    }
}

/// Represents an in-memory RSA key.
public struct RSAKey {
    /// Supported RSA key types.
    public enum Kind {
        /// A public RSA key. Used for verifying signatures.
        case `public`
        /// A private RSA key. Used for creating and verifying signatures.
        case `private`
    }

    // MARK: Static

    /// Creates a new `RSAKey` from a private key pem file.
    public static func `private`<Data>(pem: Data) -> RSAKey
        where Data: DataProtocol
    {
        return .init(type: .private, key: .make(type: .private, from: pem))
    }

    /// Creates a new `RSAKey` from a public key pem file.
    public static func `public`<Data>(pem: Data) -> RSAKey
        where Data: DataProtocol
    {
        return .init(type: .public, key: .make(type: .public, from: pem))
    }

    /// Creates a new `RSAKey` from a public key certificate file.
    public static func `public`<Data>(certificate: Data) -> RSAKey
        where Data: DataProtocol
    {
        return .init(type: .public, key: .make(type: .public, from: certificate, x509: true))
    }

    // MARK: Properties
    /// The specific RSA key type. Either public or private.
    ///
    /// Note: public keys can only verify signatures. A private key
    /// is required to create new signatures.
    public var type: Kind

    /// The C OpenSSL key ref.
    fileprivate let c: CRSAKey

    // MARK: Init

    /// Creates a new `RSAKey` from a public or private key.
    fileprivate init(type: Kind, key: CRSAKey) {
        self.type = type
        self.c = key
    }

    /// Creates a new `RSAKey` from components.
    ///
    /// For example, if you want to use Google's [public OAuth2 keys](https://www.googleapis.com/oauth2/v3/certs),
    /// you could parse the request using:
    ///
    ///     struct CertKeysResponse: APIResponse {
    ///         let keys: [Key]
    ///
    ///         struct Key: Codable {
    ///             let kty: String
    ///             let alg: String
    ///             let kid: String
    ///
    ///             let n: String
    ///             let e: String
    ///             let d: String?
    ///         }
    ///     }
    ///
    /// And then instantiate the key as:
    ///
    ///     try RSAKey.components(n: key.n, e: key.e, d: key.d)
    ///
    /// - throws: `CryptoError` if key generation fails.
    public static func components(n: String, e: String, d: String? = nil) -> RSAKey {
        guard let rsa = RSA_new() else {
            fatalError("RSA key creation failed")
        }

        let n = parseBignum(n)
        let e = parseBignum(e)
        let d = d.flatMap { parseBignum($0) }
        RSA_set0_key(rsa, n, e, d)
        return .init(type: d == nil ? .public : .private, key: CRSAKey(rsa))
    }
}

// MARK: Private

private final class CRSAKey {
    let pointer: OpaquePointer

    internal init(_ pointer: OpaquePointer) {
        self.pointer = pointer
    }

    static func make<Data>(type: RSAKey.Kind, from data: Data, x509: Bool = false) -> CRSAKey
        where Data: DataProtocol
    {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        let bytes = data.copyBytes()
        let nullTerminatedData = bytes + [0]
        _ = nullTerminatedData.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Int32 in
            return BIO_puts(bio, p.baseAddress?.assumingMemoryBound(to: Int8.self))
        }

        let maybePkey: OpaquePointer?

        if x509 {
            guard let x509 = PEM_read_bio_X509(bio, nil, nil, nil) else {
                fatalError("Key creation from certificate failed")
            }

            defer { X509_free(x509) }
            maybePkey = X509_get_pubkey(x509)
        } else {
            switch type {
            case .public: maybePkey = PEM_read_bio_PUBKEY(bio, nil, nil, nil)
            case .private: maybePkey = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
            }
        }

        guard let pkey = maybePkey else {
            fatalError("RSA key creation failed")
        }
        defer { EVP_PKEY_free(pkey) }

        guard let rsa = EVP_PKEY_get1_RSA(pkey) else {
            fatalError("RSA key creation failed")
        }
        return .init(rsa)
    }

    deinit { RSA_free(self.pointer) }
}

private func parseBignum(_ s: String) -> OpaquePointer {
    return Data(s.utf8).base64URLDecodedBytes().withUnsafeBytes { (p: UnsafeRawBufferPointer) -> OpaquePointer in
        return BN_bin2bn(p.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(p.count), nil)
    }
}

private struct RSAAlgorithm: JWTAlgorithm {
    let key: RSAKey
    let algorithm: OpaquePointer
    let jwtAlgorithmName: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        switch key.type {
        case .public:
            throw JWTError(identifier: "rsa", reason: "Cannot create RSA signature with a public key. A private key is required.")
        case .private:
            break
        }

        var siglen: UInt32 = 0
        var signature = [UInt8](
            repeating: 0,
            count: Int(RSA_size(key.c.pointer))
        )

        guard self.hash(plaintext).withUnsafeBytes ({ inputBuffer in
            signature.withUnsafeMutableBytes({ signatureBuffer in
                RSA_sign(
                    EVP_MD_type(self.algorithm),
                    inputBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt32(inputBuffer.count),
                    signatureBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    &siglen,
                    key.c.pointer
                )
            })
        }) == 1 else {
            throw JWTError(identifier: "rsaSign", reason: "RSA signature creation failed")
        }

        return signature
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        return self.hash(plaintext).withUnsafeBytes({ inputBuffer in
            signature.copyBytes().withUnsafeBytes({ signatureBuffer in
                RSA_verify(
                    EVP_MD_type(self.algorithm),
                    inputBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt32(inputBuffer.count),
                    signatureBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt32(signatureBuffer.count),
                    key.c.pointer
                )
            })
        }) == 1
    }

    private func hash<Plaintext>(_ plaintext: Plaintext) -> [UInt8]
        where Plaintext: DataProtocol
    {
        let context = EVP_MD_CTX_new()
        defer { EVP_MD_CTX_free(context) }

        guard EVP_DigestInit_ex(context, self.algorithm, nil) == 1 else {
            fatalError("Failed initializing digest context")
        }
        guard plaintext.copyBytes().withUnsafeBytes({
            EVP_DigestUpdate(context, $0.baseAddress, $0.count)
        }) == 1 else {
            fatalError("Failed updating digest")
        }
        var hash: [UInt8] = .init(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0

        guard hash.withUnsafeMutableBytes({
            EVP_DigestFinal_ex(context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), &count)
        }) == 1 else {
            fatalError("Failed finalizing digest")
        }
        return .init(hash[0..<Int(count)])
    }
}
