import PackageDescription

let package = Package(
    name: "VaporJWT",
    dependencies: [
        .Package(url: "https://github.com/vapor/Crypto.git", majorVersion: 1),
        .Package(url: "https://github.com/vapor/JSON.git", majorVersion: 1),
    ]
)
