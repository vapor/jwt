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
        <img src="https://design.vapor.codes/images/swift62up.svg" alt="Swift 6.2+">
    </a>
</p>
<br>

Support for JWT (JSON Web Tokens) in Vapor.
This package integrates [JWTKit](https://github.com/vapor/jwt-kit.git) with Vapor.

### Installation

Use the SPM string to easily include the package in your `Package.swift` file.

```swift
.package(url: "https://github.com/vapor/jwt.git", from: "5.0.0")
```

and add it to your target's dependencies:

```swift
.product(name: "JWT", package: "jwt")
```

### Verifying identity tokens

Identity tokens must be verified against the audience identifiers your application accepts (client IDs for Apple, Google, and Microsoft; project IDs for Firebase). For a provider helper, pass `applicationIdentifier` or configure it on `app.jwt.apple`, `app.jwt.google`, `app.jwt.microsoft`, or `app.jwt.firebaseAuth`:

```swift
let token = try await req.jwt.apple.verify(applicationIdentifier: appleClientID)
```

When one endpoint accepts several audience identifiers, pass all of them to `expectedAudiences`:

```swift
let token = try await req.jwt.google.verify(
    expectedAudiences: [webClientID, mobileClientID]
)
```

For generic verification, pass `expectedAudience` or `expectedAudiences` directly:

```swift
let token = try await req.jwt.verify(
    as: AppleIdentityToken.self,
    expectedAudience: appleClientID
)
```

The verifier requires at least one expected ID in the token's `aud` claim. Any other IDs in `aud` must also be expected or explicitly listed in `trustedAdditionalAudiences`.

A Google mobile app can request a token for a backend server client ID. In that case, `aud` is the server client ID and `azp` can be the mobile client ID. Verify the server ID as the audience; `azp` is unrestricted by default. To restrict the presenter too, pass `trustedAuthorizedPresenters` to the Google helper.

A call without an expected audience verifies the signature and other claims but does not establish that the token was issued for your application. Accepting it as a login is insecure. The audience-free identity-token overload is deprecated, and the request and provider helpers log a warning when they use it. Calls through a generic `JWTPayload` constraint may not produce a compile-time warning.
