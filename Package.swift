// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "JWT",
    products: [
        .library(name: "JWT", targets: ["JWT"]),
    ],
    dependencies: [
        // Cryptography modules
        .package(url: "https://github.com/vapor/crypto.git", .exact("1.0.0-beta.1")),
    ],
    targets: [
        .target(name: "JWT", dependencies: ["Crypto"]),
        .testTarget(name: "JWTTests", dependencies: ["JWT"]),
    ]
)
