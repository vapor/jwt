<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/vapor/jwt/assets/1130717/8c1b20b9-af69-43e3-899f-fb575fad9fb7">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/vapor/jwt/assets/1130717/c8f4c9f2-fbc6-46e5-89e7-f10ac17bb1a4">
        <img src="https://github.com/vapor/jwt/assets/1130717/bdc5befe-01c4-4e50-a203-c6ef71e16394" height="96" alt="JWTKit">
    </picture> 
    <br>
    <br>
    <a href="https://docs.vapor.codes/4.0/">
        <img src="https://design.vapor.codes/images/readthedocs.svg" alt="Documentation">
    </a>
    <a href="https://discord.gg/vapor">
        <img src="https://design.vapor.codes/images/discordchat.svg" alt="Team Chat">
    </a>
    <a href="LICENSE">
        <img src="https://design.vapor.codes/images/mitlicense.svg" alt="MIT License">
    </a>
    <a href="https://github.com/vapor/jwt/actions/workflows/test.yml">
        <img src="https://img.shields.io/github/actions/workflow/status/vapor/jwt/test.yml?event=push&style=plastic&logo=github&label=tests&logoColor=%23ccc" alt="Continuous Integration">
    </a>
    <a href="https://swift.org">
        <img src="https://design.vapor.codes/images/swift510up.svg" alt="Swift 5.10+">
    </a>
</p>
<br>

Support for JWT (JSON Web Tokens) in Vapor.

### Installation

Use the SPM string to easily include the package in your `Package.swift` file.

```swift
.package(url: "https://github.com/vapor/jwt.git", from: "5.0.0")
```

and add it to your target's dependencies:

```swift
.product(name: "JWT", package: "jwt")
```
