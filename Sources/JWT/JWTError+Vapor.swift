import Vapor

// Wrap JWTKit's error so we have better control over it, can set a reason etc
public struct JWTErrorWrapper: AbortError {
    let underlying: JWTError
    
    public var status: HTTPResponseStatus {
        .unauthorized
    }
    
    public var reason: String {
        underlying.reason ?? status.description
    }
}
