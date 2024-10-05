import Vapor

struct LoginResponse: Content {
    var token: String
}
