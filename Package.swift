// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "JWT",
    products: [
        .library(name: "JWT", targets: ["JWT"]),
    ],
    dependencies: [
        // Cryptography modules
        .package(url: "https://github.com/vapor/crypto.git", "3.0.0-beta.1"..<"3.0.0-beta.2"),
    ],
    targets: [
        .target(name: "JWT", dependencies: ["Crypto"]),
        .testTarget(name: "JWTTests", dependencies: ["JWT"]),
    ]
)
