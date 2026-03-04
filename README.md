# Microsoft Entra ID Authentication Provider

OAuth implementation that includes:
- error handling, with onError hook
- client credential token acquisition
- on-behalf-of (OBO) token exchange
- token request timeout config
- type safe OBO token exchange - applications will auto complete when calling methods

### Example:

```typescript
const authProvider = new AuthProvider({
	clientId: "eebaf813-5016-4c25-927b-60d655a09c2f",
	clientSecret: "my-super-secret",
	tenantId: "b7c4902c-cc47-4c0f-b347-7093ef5516aa",
	scopes: [
		"api://eebaf813-5016-4c25-927b-60d655a09c2f/access-as",
		"offline_access",
		"openid",
		"profile",
		"email",
		"User.Read",
	],
	redirectUri: "https://example.com/auth/callback",
	oboApplications: {
		api1: { // Some human readable key or you could use the applications uuid.
			scopes: [
                "api://70e35c7f-7829-4a2a-a230-f0391cf0c097/access-as",
                "offline_access",
            ],
		},
	},
    // Error callback hook that provides the exception that occurred
    onError: (error) => {
        Sentry.captureException(error),
    },
    timeout: 5000, // Timeout after 5 seconds.
});

// Creating the url for start of OAuth2.0 flow:
const { 
    codeVerifier, // AKA "nonce"
    state, 
    url,
} = await createAuthProvider.createAuthorizationURL();

// After auth redirect your route handler will use this to get the users token, session and user details:
const { 
    data: sessionData, 
    error: codeVerificationError,
} = await createAuthProvider.validateAuthorizationCode(
    "code-provided-from-oauth-flow", 
    codeVerifier, // AKA "nonce"
    state
);

// Provide the refresh token and the application if refreshing for an obo token:
const { 
    data: oboRefreshedSession, 
    error: oboRefreshError,
} = await authProvider.refreshAccessToken(
    "some-obo-app-refresh-token",
    "api1"
);

// Leave application id blank to refresh the application's token:
const { 
    data: refreshSession, 
    error: refreshError 
} = await authProvider.refreshAccessToken(
    "some-app-refresh-token"
);

// Use this when the application itself needs to get a token for another api:
const { 
    data: clientToken,
    error: clientTokenError,
} = await createAuthProvider.acquireTokenByClientCredential(
    "api1", // Type safe and based off of oboApplications configured via the provider.
);

// Use this when you want to exchange a user's token for that of another api:
const { 
    data: userToken, 
    error: userTokenError,
} = await createAuthProvider.acquireTokenOnBehalfOf(
    "api1", // Type safe and based off of oboApplications configured via the provider.
    "some-access-token" // Users access token from main application.
);
```

## Config

To ensure that you get back a refresh token when authenticating with 
microsoft, make sure you include `offline_access` in your application 
scope.

To get all the data required to generate a user, you will also need to
include `openid`, `email`, `profile`, and `User.Read` scopes, and ensure
that these scopes have been added in the MS Entra ID application, by adding
graph to the application permissions.

If you're using any APIs requiring OBO tokens ensure that you include your
application's api scope in the scopes config array. Something like: 
`api://eebaf813-5016-4c25-927b-60d655a09c2f/access-as`, where the UUID 
is your applications id or a custom name you provided, and 
`access-as` is the suffix added when creating the API scope.

OBO applications require at least their API scope to be provided or the
token exchange will failed. Also ensure that the main application has 
the permissions to access this API.

## Development

- Install dependencies:

```bash
pnpm install
```

- Run the unit tests:

```bash
pnpm test
```

- Build the library:

```bash
pnpm build
```

## Tech used

- [Arctic](https://arcticjs.dev/) for OAuth flow.
- [@oslojs/crypto](https://www.npmjs.com/package/@oslojs/crypto) for cryptography.
- [@oslojs/encoding](https://www.npmjs.com/package/@oslojs/encoding) for encoding session tokens.
- [zod](https://zod.dev/) for token schema validation.
