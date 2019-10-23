import Foundation

public extension JWK {
    public enum KeyOperation: String, Codable {
        /// Compute digital signature or MAC.
        case sign
        /// Verify digital signature or MAC.
        case verify
        /// Encrypt content.
        case encrypt
        /// Decrypt content and validate decryption, if applicable.
        case decrypt
        /// Encrypt key.
        case wrapKey
        /// Decrypt key and validate decryption, if applicable.
        case unwrapKey
        /// Derive key.
        case deriveKey
        /// Derive bits not to be used as a key.
        case deriveBits
    }
}
