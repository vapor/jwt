import JWT
import Vapor

struct TestUser: Content, Authenticatable, JWTPayload {
    var name: String

    func verify(using _: some JWTAlgorithm) throws {
        // nothing to verify
    }
}
