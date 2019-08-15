import CJWTKitCrypto

extension JWTSigner {
    // MARK: HMAC

    public static func hs256<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACSigner(
            key: key.copyBytes(),
            algorithm: convert(EVP_sha256()),
            name: "HS256"
        ))
    }
    
    public static func hs384<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACSigner(
            key: key.copyBytes(),
            algorithm: convert(EVP_sha384()),
            name: "HS384"
        ))
    }
    
    public static func hs512<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACSigner(
            key: key.copyBytes(),
            algorithm: convert(EVP_sha512()),
            name: "HS512"
        ))
    }
}

// MARK: Private

private enum HMACError: Error {
    case initializationFailure
    case updateFailure
    case finalizationFailure
}

private struct HMACSigner: JWTAlgorithm {
    let key: [UInt8]
    let algorithm: OpaquePointer
    let name: String
    
    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        var context = HMAC_CTX()
        defer { HMAC_CTX_cleanup(&context) }
        
        guard self.key.withUnsafeBytes({
            return HMAC_Init_ex(&context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32($0.count), convert(self.algorithm), nil)
        }) == 1 else {
            throw JWTError.signingAlgorithmFailure(HMACError.initializationFailure)
        }
        
        guard plaintext.copyBytes().withUnsafeBytes({
            return HMAC_Update(&context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count)
        }) == 1 else {
            throw JWTError.signingAlgorithmFailure(HMACError.updateFailure)
        }
        var hash = [UInt8](repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0
        
        guard hash.withUnsafeMutableBytes({
            return HMAC_Final(&context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), &count)
        }) == 1 else {
            throw JWTError.signingAlgorithmFailure(HMACError.finalizationFailure)
        }
        return .init(hash[0..<Int(count)])
    }
}
