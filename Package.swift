// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "JWT",
    products: [
        .library(name: "JWT", targets: ["JWT"]),
    ],
    dependencies: [
        // 🌎 Utility package containing tools for byte manipulation, Codable, OS APIs, and debugging.
        .package(url: "https://github.com/vapor/core.git", .branch("master")),

        // 🔑 Hashing (BCrypt, SHA, HMAC, etc), encryption, and randomness.
        .package(url: "https://github.com/vapor/crypto.git", .branch("master")),
    ],
    targets: [
        .target(name: "JWT", dependencies: ["Core", "Crypto"]),
        .testTarget(name: "JWTTests", dependencies: ["JWT"]),
    ]
)
