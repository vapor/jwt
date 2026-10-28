# ``JWT``

JWT provides integrations between [JWTKit](https://github.com/vapor/jwt-kit) and [Vapor](https://github.com/vapor/vapor) to make it easy to work with JWTs in your Vapor application.

For more details, see the [Vapor Docs](https://docs.vapor.codes/security/jwt/).

## Verifying identity tokens

Identity tokens must be verified against the audience identifiers accepted by the application (client IDs for Apple, Google, and Microsoft; project IDs for Firebase). Provider helpers accept `applicationIdentifier`, or use the identifier configured on `app.jwt.apple`, `app.jwt.google`, `app.jwt.microsoft`, or `app.jwt.firebaseAuth`:

```swift
let token = try await req.jwt.apple.verify(applicationIdentifier: appleClientID)
```

For an endpoint that accepts several audience identifiers, use `expectedAudiences`:

```swift
let token = try await req.jwt.google.verify(
    expectedAudiences: [webClientID, mobileClientID]
)
```

Generic identity-token verification accepts `expectedAudience` or `expectedAudiences`:

```swift
let token = try await req.jwt.verify(
    as: AppleIdentityToken.self,
    expectedAudience: appleClientID
)
```

At least one expected ID must appear in `aud`. Any other audience values must be expected IDs or explicitly trusted through `trustedAdditionalAudiences`.

In Google mobile sign-in, a token requested for a backend server client ID can have that ID in `aud` and the mobile client ID in `azp`. Verify the server client ID as the audience. The default does not restrict `azp`; use `trustedAuthorizedPresenters` on the Google helper if the application needs to restrict presenting clients.

An audience-free call verifies the signature and other claims without checking whether the token was issued for your application. Accepting the token as a login is insecure. Such identity-token calls are deprecated, and the request and provider helpers log a warning when they use them. Calls through a generic `JWTPayload` constraint may not receive a compile-time warning.
