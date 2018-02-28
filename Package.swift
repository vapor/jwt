// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "JWT",
    products: [
        .library(name: "JWT", targets: ["JWT"]),
    ],
    dependencies: [
        // 🔑 Hashing (BCrypt, SHA, HMAC, etc), encryption, and randomness.
        .package(url: "https://github.com/vapor/crypto.git", from: "3.0.0-rc"),
    ],
    targets: [
        .target(name: "JWT", dependencies: ["Crypto"]),
        .testTarget(name: "JWTTests", dependencies: ["JWT"]),
    ]
)
