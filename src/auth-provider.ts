import { sha256 } from "@oslojs/crypto/sha2";
import { encodeBase32, encodeHexLowerCase } from "@oslojs/encoding";
import {
	decodeIdToken,
	generateCodeVerifier,
	generateState,
	MicrosoftEntraId,
	OAuth2Tokens,
} from "arctic";
import {
	AcquireTokenByClientCredentialError,
	AcquireTokenOnBehalfOfError,
	tryCatch,
	tryCatchSync,
} from "./error-handling";
import type {
	AcquireTokenOnBehalfOfProps,
	AuthorizationUrl,
	AuthProviderCallbacks,
	AuthProviderProps,
	AuthProviderResponse,
	IAuthProvider,
	RefreshAccessTokenProps,
	ValidateAuthorizationCodeProps,
} from "./types";

/**
 * AuthProvider is a class that provides methods for handling authentication with Microsoft Entra ID.
 * It supports validating authorization codes, refreshing access tokens, acquiring tokens on behalf
 * of users, and acquiring tokens using client credentials. The class is designed to be flexible
 * and can be configured with different applications and scopes.
 */
export class AuthProvider implements IAuthProvider {
	private readonly callbacks?: AuthProviderCallbacks;

	/** The timeout for the authentication requests. */
	readonly timeout?: number;

	private readonly clientSecret: string;
	readonly textEncoder = new TextEncoder();
	readonly entraId: MicrosoftEntraId;

	/** The client ID for the application. */
	readonly clientId: string;
	/** The URL for the Microsoft OAuth endpoint. */
	readonly microsoftOAuthUrl: string;
	/** The redirect URI for the application. */
	readonly redirectUri: string;
	/** The tenant ID for the Microsoft Entra ID. */
	readonly tenantId: string;

	constructor({
		clientId,
		clientSecret,
		tenantId,
		redirectUri,
		timeout,
		callbacks,
	}: AuthProviderProps) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.microsoftOAuthUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
		this.tenantId = tenantId;
		this.redirectUri = redirectUri;
		this.timeout = timeout;
		this.callbacks = callbacks;

		this.entraId = new MicrosoftEntraId(
			tenantId,
			clientId,
			clientSecret,
			redirectUri,
		);
	}

	decodeIdToken = tryCatchSync((idToken: string) => decodeIdToken(idToken));

	private getTimeout() {
		if (!this.timeout) return;

		const controller = new AbortController();
		const abortTimeout = setTimeout(() => controller.abort(), this.timeout);
		return {
			signal: controller.signal,
			abortTimeout,
			clearAbortTimeout: () => {
				clearTimeout(abortTimeout);
			},
		};
	}

	/**
	 * Refreshes an access token using a refresh token. Optionally accepts an application ID to determine the scopes for the new token.
	 */
	refreshAccessToken = tryCatch(
		async ({
			refreshToken,
			scopes,
		}: RefreshAccessTokenProps): Promise<AuthProviderResponse> => {
			const oauth2Tokens = await this.entraId.refreshAccessToken(
				refreshToken,
				scopes,
			);
			const token = this.generateSessionToken();
			return {
				oauth2Tokens,
				token,
				sessionId: this.generateSessionId(token),
			};
		},
		this.callbacks,
	);

	/**
	 * Validates an authorization code received from the Microsoft Entra ID authorization endpoint.
	 * Exchanges the code for tokens and extracts user information to create a session.
	 */
	validateAuthorizationCode = tryCatch(
		async ({
			code,
			codeVerifier,
		}: ValidateAuthorizationCodeProps): Promise<AuthProviderResponse> => {
			const oauth2Tokens = await this.entraId.validateAuthorizationCode(
				code,
				codeVerifier,
			);
			const token = this.generateSessionToken();
			return {
				oauth2Tokens,
				token,
				sessionId: this.generateSessionId(token),
			};
		},
		this.callbacks,
	);

	/**
	 * Creates an authorization URL for the Microsoft Entra ID authorization endpoint.
	 * Generates a random state and code verifier for PKCE.
	 * @returns An object containing the authorization URL, state, and code verifier.
	 */
	createAuthorizationURL(scopes: string[]): AuthorizationUrl {
		const state = generateState();
		const codeVerifier = generateCodeVerifier();

		const url = this.entraId.createAuthorizationURL(
			state,
			codeVerifier,
			scopes,
		);
		url.searchParams.set("nonce", codeVerifier);

		return { url, state, codeVerifier };
	}

	/**
	 * Generates a session token.
	 * @returns The generated session token.
	 */
	generateSessionToken() {
		const tokenBytes = new Uint8Array(20);
		crypto.getRandomValues(tokenBytes);
		const token = encodeBase32(tokenBytes).toLowerCase();
		return token;
	}

	/**
	 * Generates a session ID based on a session token.
	 * @param token The session token to generate an ID for.
	 * @returns The generated session ID.
	 */
	generateSessionId(token: string) {
		return encodeHexLowerCase(sha256(this.textEncoder.encode(token)));
	}

	/**
	 * Acquires a token on behalf of a user for a specified application using the OBO flow.
	 * Intended to be used in scenarios where you have an access token for a user and need to call another API on their behalf.
	 */
	acquireTokenOnBehalfOf = tryCatch(
		async ({
			accessToken,
			scopes,
		}: AcquireTokenOnBehalfOfProps): Promise<AuthProviderResponse> => {
			const body = new URLSearchParams({
				grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
				client_id: this.clientId,
				client_secret: this.clientSecret,
				assertion: accessToken,
				scope: scopes.join(" "),
				requested_token_use: "on_behalf_of",
			});

			const timeout = this.getTimeout();
			const response = await fetch(this.microsoftOAuthUrl, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body,
				signal: timeout?.signal,
			});
			timeout?.clearAbortTimeout();

			if (!response.ok) {
				throw new AcquireTokenOnBehalfOfError({
					message: "Failed to acquire token on behalf of user",
					body: body.toString(),
					status: response.status,
					statusText: response.statusText,
					props: {
						scopes,
					},
				});
			}

			const json = await response.json();
			const oauth2Tokens = new OAuth2Tokens(json as object);
			const token = this.generateSessionToken();
			return {
				oauth2Tokens,
				sessionId: this.generateSessionId(token),
				token,
			};
		},
		this.callbacks,
	);

	/**
	 * Acquires a token using the client credentials flow for a specified application.
	 * Uses the configured defaultScope. Intended to be used for service-to-service
	 * authentication where no user context is required.
	 */
	acquireTokenByClientCredential = tryCatch(
		async (scopes: string[]): Promise<AuthProviderResponse> => {
			const body = new URLSearchParams({
				client_id: this.clientId,
				client_secret: this.clientSecret,
				grant_type: "client_credentials",
				scope: scopes.join(" "),
			});

			const timeout = this.getTimeout();
			const response = await fetch(this.microsoftOAuthUrl, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body,
			});
			timeout?.clearAbortTimeout();

			if (!response.ok) {
				throw new AcquireTokenByClientCredentialError({
					message: "Failed to acquire token by client credential",
					body: body.toString(),
					status: response.status,
					statusText: response.statusText,
					props: {
						scopes,
					},
				});
			}

			const json = await response.json();
			const oauth2Tokens = new OAuth2Tokens(json as object);
			const token = this.generateSessionToken();
			return {
				token,
				oauth2Tokens,
				sessionId: this.generateSessionId(token),
			};
		},
		this.callbacks,
	);
}
