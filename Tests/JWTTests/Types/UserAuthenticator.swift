import JWT
import Vapor

struct UserAuthenticator: JWTAuthenticator {
    typealias Payload = TestUser

    func authenticate(jwt: TestUser, for request: Request) async throws {
        if jwt.name == "foo" {
            // Requiring this specific username makes the test for the guard middleware in testMiddleware() valid.
            request.auth.login(jwt)
        }
    }
}
