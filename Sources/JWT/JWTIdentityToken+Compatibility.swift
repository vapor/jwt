import Foundation
import JWTKit

/// Keeps the audience-free path available for existing provider helper calls.
/// The caller must log that it did not check the audience.
func verifyIdentityTokenWithoutAudience<Payload: JWTPayload>(
    _ message: some DataProtocol & Sendable,
    as _: Payload.Type,
    using keys: JWTKeyCollection
) async throws -> Payload {
    try await keys.verify(message, as: Payload.self)
}
