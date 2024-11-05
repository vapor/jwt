import Vapor

extension JWTError: @retroactive AbortError {
    public var reason: String {
        self.description
    }

    public var status: HTTPResponseStatus {
        .unauthorized
    }
}
