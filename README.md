# Microsoft Entra ID Authentication Provider

[![npm version](https://img.shields.io/npm/v/entra-id-auth-provider)](https://www.npmjs.com/package/entra-id-auth-provider)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

TypeScript OAuth 2.0 implementation for authenticating with Microsoft Entra ID. Supports client credentials, authorization code flow, and on-behalf-of (OBO) token exchange with full type safety.

## Installation

```bash
pnpm add entra-id-auth-provider
```

## Prerequisites

Please ensure that you understand the basics of OAuth2.0 and how to setup and configure Microsoft Entra ID applications.
- [Authorization Code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [On-Behalf-Of (OBO) flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)

## Example

```typescript
import { AuthProvider } from "entra-id-auth-provider";

const authProvider = new AuthProvider({
	clientId: process.env.ENTRA_CLIENT_ID,
	clientSecret: process.env.ENTRA_CLIENT_SECRET,
	tenantId: process.env.ENTRA_TENANT_ID,
	redirectUri: process.env.ENTRA_REDIRECT_URI,
	onError: (error) => {
		console.error("Auth error:", error);
	},
	timeout: 5000,
});

// Create authorization URL for OAuth2.0 flow:
const { 
    codeVerifier,
    state, 
    url,
} = authProvider.createAuthorizationURL([
    "openid",
    "profile", 
    "email",
    "offline_access",
]);

// After redirect, validate the authorization code:
const { 
    data: sessionData, 
    error: codeVerificationError,
} = await authProvider.validateAuthorizationCode({
    code: "code-provided-from-oauth-flow",
    codeVerifier: codeVerifier,
});

// Refresh token:
const { 
    data: refreshSession, 
    error: refreshError 
} = await authProvider.refreshAccessToken({
    refreshToken: "some-refresh-token",
    scopes: ["openid", "profile", "email"],
});

// Client credential flow (app-only token):
const { 
    data: clientToken,
    error: clientTokenError,
} = await authProvider.acquireTokenByClientCredential([
    "https://graph.microsoft.com/.default",
]);

// On-behalf-of exchange (exchange user's token for another API):
const { 
    data: userToken, 
    error: userTokenError,
} = await authProvider.acquireTokenOnBehalfOf({
    accessToken: "some-access-token",
    scopes: ["https://graph.microsoft.com/.default"],
});
```

## Configuration

### AuthProvider Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `clientId` | `string` | Yes | Your Azure AD application (client) ID |
| `clientSecret` | `string` | Yes | Client secret for your application |
| `tenantId` | `string` | Yes | Your Azure AD tenant ID |
| `redirectUri` | `string` | Yes | URI to redirect after authentication |
| `onError` | `(error: Error) => void` | No | Error callback hook |
| `timeout` | `number` | No | Request timeout in milliseconds |

### Return Values

All methods return `{ data, error }` where:
- `data`: The requested data (session, token, etc.) on success
- `error`: An error object if something went wrong

## SessionProvider

The `SessionProvider` extends `AuthProvider` and provides session management functionality for storing and retrieving sessions (e.g., in a database or cookies). Use this when you need to manage user sessions with persistent storage.

### SessionProvider Options

Inherits all [AuthProvider options](#authprovider-options), plus:

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `sessionCallbacks` | `object` | Yes | Callbacks for session storage operations |

### SessionCallbacks

| Callback | Type | Description |
|----------|------|-------------|
| `select` | `(sessionId: string) => Promise<AuthProviderResponse \| null>` | Retrieve a session from storage |
| `delete` | `(sessionId: string) => Promise<void>` | Remove a session from storage |
| `insert` | `(authTokens: AuthProviderResponse) => Promise<void>` | Save a new session to storage |

### SessionProvider Methods

| Method | Description |
|--------|-------------|
| `get(props)` | Get a session by token. Automatically refreshes if expired. Returns `null` if not found. |
| `getObo(props)` | Get or acquire an OBO (On-Behalf-Of) session. Automatically exchanges tokens if needed. |
| `delete(props)` | Delete a session by token or sessionId. |

### SessionProvider Usage Example

```typescript
import { SessionProvider } from "entra-id-auth-provider";

const sessionProvider = new SessionProvider({
    clientId: process.env.ENTRA_CLIENT_ID,
    clientSecret: process.env.ENTRA_CLIENT_SECRET,
    tenantId: process.env.ENTRA_TENANT_ID,
    redirectUri: process.env.ENTRA_REDIRECT_URI,
    sessionCallbacks: {
        select: async (sessionId) => {
            // Retrieve from your database/cookie store
            // Note: you will need to wrap the results in OAuth2Tokens object. And wrap that in AuthProviderResponse
            return await db.sessions.findUnique({ where: { sessionId } });
        },
        delete: async (sessionId) => {
            // Remove from your database/cookie store
            await db.sessions.delete({ where: { sessionId } });
        },
        insert: async (authTokens) => {
            // Save to your database/cookie store
            // If idToken needs to be used to create the user
            // make sure to use decodeIdToken in conjunction with a schema or something.
            await db.sessions.create({ data: authTokens });
        },
    },
});

// Get session (auto-refreshes if expired)
const session = await sessionProvider.get({
    token: "user-session-token",
    scopes: ["openid", "profile", "email"],
});

// Get or acquire OBO token
const oboSession = await sessionProvider.getObo({
    token: "user-session-token",
    scopes: ["openid", "profile"],
    oboToken: "obo-session-token",
    oboScopes: ["https://graph.microsoft.com/.default"],
});

// Delete session
await sessionProvider.delete({ token: "user-session-token" });
```

### GetSessionProps

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `token` | `string` | Yes | The session token |
| `scopes` | `string[]` | Yes | OAuth |
| `readonly scopes to useCookies` | `boolean` | No | If `false`, saves refreshed tokens to storage (default: `true`) |

### GetOboSessionProps

Extends `GetSessionProps` with:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `oboToken` | `string` | Yes | The OBO session token |
| `oboScopes` | `string[]` | Yes | The scopes for the OBO token |

## Required Scopes

To receive a refresh token, include `offline_access` in your scopes.

To get user profile data, include these scopes and ensure they're configured in your Azure portal:
- `openid` - Required for OIDC flow
- `email` - User email address
- `profile` - Basic profile info
- `User.Read` - Microsoft Graph API access (add via "Microsoft Graph" > "Delegated permissions" in Azure portal)

For OBO tokens, ensure your main application's API scope is included:
```
api://{application-id}/access-as
```
Where `access-as` is the suffix you defined when creating the API scope in Azure AD. Also verify the main application has permission to call the OBO API in the Azure portal under "Expose an API".

## Troubleshooting

### "AADSTS7000215: Invalid client secret"
- Ensure your client secret is correct and hasn't expired
- Check the secret in Azure portal under "Certificates & secrets"

### "AADSTS700016: Application not found"
- Verify `clientId` matches your application ID in Azure portal
- Ensure the application is enabled in Azure AD

### OBO token exchange fails
- Verify the main app has "Access tokens" and "ID tokens" enabled in Azure portal authentication settings
- Ensure user has consented to the required permissions
- Make sure the access token has the appropriate scopes for the OBO flow

### No refresh token returned
- Must include `offline_access` scope
- In Azure portal, check "Allow offline access" is enabled in authentication settings

## Development

```bash
pnpm install
pnpm test
pnpm build
pnpm typecheck
```

## License

MIT License - see [LICENSE](LICENSE) for details.
