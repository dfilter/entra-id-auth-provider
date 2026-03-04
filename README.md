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
	scopes: [
		"api://eebaf813-5016-4c25-927b-60d655a09c2f/access-as",
		"offline_access",
		"openid",
		"profile",
		"email",
		"User.Read",
	],
	redirectUri: process.env.ENTRA_REDIRECT_URI,
	oboApplications: {
		api1: {
			scopes: [
                "api://70e35c7f-7829-4a2a-a230-f0391cf0c097/access-as",
                "offline_access",
            ],
		},
	},
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
} = await authProvider.createAuthorizationURL();

// After redirect, validate the authorization code:
const { 
    data: sessionData, 
    error: codeVerificationError,
} = await authProvider.validateAuthorizationCode(
    "code-provided-from-oauth-flow", 
    codeVerifier,
    state
);

// Refresh OBO token (provide app key for OBO, none for main app):
const { 
    data: oboRefreshedSession, 
    error: oboRefreshError,
} = await authProvider.refreshAccessToken(
    "some-obo-app-refresh-token",
    "api1"
);

const { 
    data: refreshSession, 
    error: refreshError 
} = await authProvider.refreshAccessToken(
    "some-app-refresh-token"
);

// Client credential flow (app-only token):
const { 
    data: clientToken,
    error: clientTokenError,
} = await authProvider.acquireTokenByClientCredential(
    "api1",
);

// On-behalf-of exchange (exchange user's token for another API):
const { 
    data: userToken, 
    error: userTokenError,
} = await authProvider.acquireTokenOnBehalfOf(
    "api1",
    "some-access-token"
);
```

## Configuration

### AuthProvider Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `clientId` | `string` | Yes | Your Azure AD application (client) ID |
| `clientSecret` | `string` | Yes | Client secret for your application |
| `tenantId` | `string` | Yes | Your Azure AD tenant ID |
| `scopes` | `string[]` | Yes | OAuth scopes to request |
| `redirectUri` | `string` | Yes | URI to redirect after authentication |
| `oboApplications` | `Record<string, { scopes: string[] }>` | No | OBO app configurations |
| `onError` | `(error: Error) => void` | No | Error callback hook |
| `timeout` | `number` | No | Request timeout in milliseconds |

### Return Values

All methods return `{ data, error }` where:
- `data`: The requested data (session, token, etc.) on success
- `error`: An error object if something went wrong

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
 value- Check the secret in Azure portal under "Certificates & secrets"

### "AADSTS700016: Application not found"
- Verify `clientId` matches your application ID in Azure portal
- Ensure the application is enabled in Azure AD

### OBO token exchange fails
- Confirm the OBO application's API scope is in `oboApplications` config
- Verify the main app has "Access tokens" and "ID tokens" enabled in Azure portal authentication settings
- Ensure user has consented to the required permissions

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
