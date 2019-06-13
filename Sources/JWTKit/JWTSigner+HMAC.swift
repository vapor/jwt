import CJWTKitOpenSSL

extension JWTSigner {
    // MARK: HMAC

    public static func hs256<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACAlgorithm(
            key: key.copyBytes(),
            algorithm: EVP_sha256(),
            jwtAlgorithmName: "HS256"
        ))
    }
    
    public static func hs384<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACAlgorithm(
            key: key.copyBytes(),
            algorithm: EVP_sha384(),
            jwtAlgorithmName: "HS384"
        ))
    }
    
    public static func hs512<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACAlgorithm(
            key: key.copyBytes(),
            algorithm: EVP_sha512(),
            jwtAlgorithmName: "HS512"
        ))
    }
}

private struct HMACAlgorithm: JWTAlgorithm {
    let key: [UInt8]
    let algorithm: OpaquePointer
    let jwtAlgorithmName: String
    
    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let context = HMAC_CTX_new()
        defer { HMAC_CTX_free(context) }
        
        guard self.key.withUnsafeBytes({
            return HMAC_Init_ex(context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32($0.count), self.algorithm, nil)
        }) == 1 else {
            fatalError("Failed initializing HMAC context")
        }
        
        guard plaintext.copyBytes().withUnsafeBytes({
            return HMAC_Update(context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count)
        }) == 1 else {
            fatalError("Failed updating HMAC digest")
        }
        var hash = [UInt8](repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0
        
        guard hash.withUnsafeMutableBytes({
            return HMAC_Final(context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), &count)
        }) == 1 else {
            fatalError("Failed finalizing HMAC digest")
        }
        return .init(hash[0..<Int(count)])
    }
}
