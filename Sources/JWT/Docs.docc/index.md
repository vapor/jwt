# ``JWT``

JWT provides integrations between [JWTKit](https://github.com/vapor/jwt-kit) and [Vapor](https://github.com/vapor/vapor) to make it easy to work with JWTs in your Vapor application.

For more details, see the [Vapor Docs](https://docs.vapor.codes/security/jwt/).

## Verifying identity tokens

Identity tokens must be verified against the audience identifiers accepted by the application (client IDs for Apple, Google, and Microsoft; project IDs for Firebase). Provider helpers accept `applicationIdentifier`, or use the identifier configured on `app.jwt.apple`, `app.jwt.google`, `app.jwt.microsoft`, or `app.jwt.firebaseAuth`:

```swift
let token = try await req.jwt.apple.verify(applicationIdentifier: appleClientID)
```

To use `req.jwt.apple.verify()` without passing the ID each time, configure it first:

```swift
app.jwt.apple.applicationIdentifier = appleClientID
```

For an endpoint that accepts several audience identifiers, use `expectedAudiences`:

```swift
let token = try await req.jwt.google.verify(
    expectedAudiences: [webClientID, mobileClientID]
)
```

Generic identity-token verification accepts `expectedAudience` or `expectedAudiences` and checks signatures using keys registered in `app.jwt.keys`:

```swift
let token = try await req.jwt.verify(
    as: AppleIdentityToken.self,
    expectedAudience: appleClientID
)
```

At least one expected ID must appear in `aud`. Any other audience values must be expected IDs or explicitly trusted through `trustedAdditionalAudiences`.

In Google mobile sign-in, a token requested for a backend server client ID can have that ID in `aud` and the mobile client ID in `azp`. Verify the server client ID as the audience. The default does not restrict `azp`; use `trustedAuthorizedPresenters` on the Google helper if the application needs to restrict presenting clients.

### Authenticating identity tokens

The no-argument `JWTPayload.authenticator()` uses generic verification and does not check the audience. For an identity token type that conforms to `Authenticatable`, when the provider's signing keys are registered in `app.jwt.keys`, use the audience-aware overload:

```swift
let protected = app.grouped(
    AppleIdentityToken.authenticator(expectedAudience: appleClientID),
    AppleIdentityToken.guardMiddleware()
)
```

If you have a custom `JWTAuthenticator` whose `Payload` is an identity token, replace it with a bearer authenticator that checks the audience. When using a provider helper to fetch its signing keys, call that helper with an expected audience. For example, with an `AppleUser` type conforming to `Authenticatable`:

```swift
struct AppleAuthenticator: AsyncBearerAuthenticator {
    let clientID: String

    func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        let token = try await request.jwt.apple.verify(bearer.token, applicationIdentifier: clientID)
        request.auth.login(AppleUser(subject: token.subject.value))
    }
}
```

If no audience is passed or configured, a provider helper still returns a signature-verified token for compatibility and logs a warning. It does not check that the token was issued for your application, so accepting it as a login is insecure. The audience-free `req.jwt.verify(as:)` and `authenticator()` calls on concrete identity token types are deprecated. Calls through a generic `JWTPayload` constraint, including custom `JWTAuthenticator` types, receive no compile-time warning; successful verification logs a runtime warning.

Pass either `applicationIdentifier` or `expectedAudiences` in a provider helper call. An explicit audience list overrides an identifier configured on `app.jwt.<provider>` for that call.
