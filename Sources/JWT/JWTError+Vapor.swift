import Vapor

extension JWTError: AbortError {
    public var status: HTTPResponseStatus {
        .unauthorized
    }
}
