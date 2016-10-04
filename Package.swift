import PackageDescription

let package = Package(
    name: "vapor-jwt",
    dependencies: [
        .Package(url: "https://github.com/vapor/crypto.git", majorVersion: 1),
        .Package(url: "https://github.com/vapor/json.git", majorVersion: 1),
    ]
)
