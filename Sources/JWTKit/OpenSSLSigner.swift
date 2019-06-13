import CJWTKitCrypto

protocol OpenSSLSigner {
    var algorithm: OpaquePointer { get }
}

extension OpenSSLSigner {
    func digest<Plaintext>(_ plaintext: Plaintext) -> [UInt8]
        where Plaintext: DataProtocol
    {
        let context = EVP_MD_CTX_new()
        defer { EVP_MD_CTX_free(context) }

        guard EVP_DigestInit_ex(context, convert(self.algorithm), nil) == 1 else {
            fatalError("Failed initializing digest context")
        }
        let plaintext = plaintext.copyBytes()
        guard EVP_DigestUpdate(context, plaintext, plaintext.count) == 1 else {
            fatalError("Failed updating digest")
        }
        var digest: [UInt8] = .init(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var digestLength: UInt32 = 0

        guard EVP_DigestFinal_ex(context, &digest, &digestLength) == 1 else {
            fatalError("Failed finalizing digest")
        }
        return .init(digest[0..<Int(digestLength)])
    }
}

protocol OpenSSLKey { }

extension OpenSSLKey {
    static func load<Data, T>(pem data: Data, _ closure: (OpaquePointer) -> (T?)) -> T
        where Data: DataProtocol
    {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        guard (data.copyBytes() + [0]).withUnsafeBytes({ pointer in
            BIO_puts(bio, pointer.baseAddress?.assumingMemoryBound(to: Int8.self))
        }) >= 0 else {
            fatalError("BIO puts failed")
        }

        guard let c = closure(convert(bio!)) else {
            fatalError("PEM_read_bio_EC_PUBKEY failed")
        }
        return c
    }
}
