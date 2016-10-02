import PackageDescription

let package = Package(
    name: "vapor-jwt",
    dependencies: [
        .Package(url: "https://github.com/vapor/JSON.git", majorVersion: 1),
    ]
)
