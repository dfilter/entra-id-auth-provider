import { sha256 } from "@oslojs/crypto/sha2";
import { encodeBase32, encodeHexLowerCase } from "@oslojs/encoding";
import {
	decodeIdToken,
	generateCodeVerifier,
	generateState,
	MicrosoftEntraId,
	type OAuth2Tokens,
} from "arctic";
import type { z } from "zod";
import {
	AcquireTokenByClientCredentialError,
	AcquireTokenOnBehalfOfError,
	tryCatch,
} from "./error-handling";
import {
	type BaseIdTokenSchema,
	defaultTokenSchema,
	oboTokenSchema,
} from "./lib/zod";
import type {
	AuthTokens,
	IAuthProviderProps,
	OboApplicationConfig,
} from "./types";

/**
 * AuthProvider is a class that provides methods for handling authentication with Microsoft Entra ID.
 * It supports validating authorization codes, refreshing access tokens, acquiring tokens on behalf
 * of users, and acquiring tokens using client credentials. The class is designed to be flexible
 * and can be configured with different applications and scopes.
 */
export class AuthProvider<
	Config extends OboApplicationConfig,
	Schema extends BaseIdTokenSchema,
> {
	/** A function to handle errors that occur during authentication. */
	onError?: <T extends Error>(error: T) => void | Promise<void>;
	/** The timeout for the authentication requests. */
	readonly timeout?: number;
	readonly idTokenSchema: Schema;

	private readonly clientSecret: string;
	private textEncoder = new TextEncoder();
	readonly entraId: MicrosoftEntraId;

	/** The client ID for the application. */
	readonly clientId: string;
	/** The URL for the Microsoft OAuth endpoint. */
	readonly microsoftOAuthUrl: string;
	/** The applications that can be used to acquire tokens on behalf of users. */
	readonly oboApplications: Config;
	/** The redirect URI for the application. */
	readonly redirectUri: string;
	/** The scopes for the application. */
	readonly scopes: string[];
	/** The tenant ID for the Microsoft Entra ID. */
	readonly tenantId: string;

	constructor({
		clientId,
		clientSecret,
		tenantId,
		redirectUri,
		onError,
		oboApplications,
		scopes,
		timeout,
		idTokenSchema,
	}: IAuthProviderProps<Config, Schema>) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.microsoftOAuthUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
		this.onError = onError;
		this.tenantId = tenantId;
		this.redirectUri = redirectUri;
		this.scopes = scopes;
		this.oboApplications = oboApplications;
		this.timeout = timeout;
		this.idTokenSchema = idTokenSchema;

		this.entraId = new MicrosoftEntraId(
			tenantId,
			clientId,
			clientSecret,
			redirectUri,
		);
	}

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
	 * @param refreshToken The refresh token to use for acquiring a new access token.
	 * @param applicationId The client ID of the application to determine scopes for the new token (optional).
	 * @param state The state value to associate with the session (optional).
	 * @returns An object containing the new session information, user details, and a new session token.
	 */
	refreshAccessToken = tryCatch(
		async (
			refreshToken: string,
			applicationId?: keyof Config,
			state?: string,
		) => {
			const scopes = applicationId
				? this.oboApplications[applicationId].scopes
				: this.scopes;
			const tokens = await this.entraId.refreshAccessToken(
				refreshToken,
				scopes,
			);

			return this.extractTokenData(tokens, state);
		},
		this.onError,
	);

	/**
	 * Validates an authorization code received from the Microsoft Entra ID authorization endpoint.
	 * Exchanges the code for tokens and extracts user information to create a session.
	 * @param code The authorization code to validate.
	 * @param codeVerifier The PKCE code verifier used in the initial authorization request.
	 * @param state The state value to associate with the session (optional).
	 * @returns An object containing the session token, session information, and user details.
	 */
	validateAuthorizationCode = tryCatch(
		async (code: string, codeVerifier: string, state: string) => {
			const tokens = await this.entraId.validateAuthorizationCode(
				code,
				codeVerifier,
			);
			return this.extractTokenData(tokens, state);
		},
		this.onError,
	);

	/**
	 * Creates an authorization URL for the Microsoft Entra ID authorization endpoint.
	 * Generates a random state and code verifier for PKCE.
	 * @returns An object containing the authorization URL, state, and code verifier.
	 */
	createAuthorizationURL() {
		const state = generateState();
		const codeVerifier = generateCodeVerifier();

		const url = this.entraId.createAuthorizationURL(
			state,
			codeVerifier,
			this.scopes,
		);
		url.searchParams.set("nonce", codeVerifier);

		return { url, state, codeVerifier };
	}

	/**
	 * For some reason there aren't any safeguards around trying to access the idToken
	 * @param tokens
	 * @returns typed id token object.
	 */
	private parseIdToken(tokens: OAuth2Tokens | string) {
		let idTokenString: string;
		if (typeof tokens === "string") {
			idTokenString = tokens;
		} else {
			if (
				!("id_token" in tokens.data && typeof tokens.data.id_token === "string")
			) {
				return null;
			}
			idTokenString = tokens.idToken();
		}

		let decodedIdToken: object;
		try {
			decodedIdToken = decodeIdToken(idTokenString);
		} catch (e) {
			this.onError?.(e instanceof Error ? e : new Error(String(e)));
			return null;
		}

		const { error, data } = this.idTokenSchema.safeParse(decodedIdToken);
		if (error) {
			this.onError?.(error);
			return null;
		}

		return data;
	}

	private extractTokenData(
		tokens: OAuth2Tokens,
		state: string | null = null,
	): AuthTokens<z.infer<typeof this.idTokenSchema>> {
		const token = this.generateSessionToken();
		return {
			accessToken: tokens.accessToken(),
			accessTokenExpiresAt: tokens.accessTokenExpiresAt(),
			accessTokenExpiresInSeconds: tokens.accessTokenExpiresInSeconds(),
			idToken: this.parseIdToken(tokens),
			refreshToken: tokens.hasRefreshToken() ? tokens.refreshToken() : null,
			scopes: tokens.hasScopes() ? tokens.scopes() : [],
			sessionId: this.generateSessionId(token),
			state,
			token,
			tokenType: tokens.tokenType(),
		};
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
	 * Converts a session token to a session ID.
	 * @param token The session token to convert.
	 * @returns The session ID.
	 */
	tokenToSessionId(token: string) {
		return encodeHexLowerCase(sha256(this.textEncoder.encode(token)));
	}

	/**
	 * Acquires a token on behalf of a user for a specified application using the OBO flow.
	 * Intended to be used in scenarios where you have an access token for a user and need to call another API on their behalf.
	 *
	 * @param applicationId - The client ID of the application for which to acquire the token.
	 * @param accessToken - The access token of the user on whose behalf to acquire the new token.
	 * @returns A promise that resolves to a Result containing either the acquired session and token or an error.
	 */
	acquireTokenOnBehalfOf = tryCatch(
		async (
			applicationId: keyof Config,
			accessToken: string,
		): Promise<AuthTokens<z.infer<typeof this.idTokenSchema>>> => {
			const body = new URLSearchParams({
				grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
				client_id: this.clientId,
				client_secret: this.clientSecret,
				assertion: accessToken,
				scope: this.oboApplications[applicationId].scopes.join(" "),
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
						applicationId,
					},
				});
			}

			const data = oboTokenSchema.parse(await response.json());
			const token = this.generateSessionToken();
			return {
				accessToken: data.access_token,
				accessTokenExpiresAt: new Date(Date.now() + data.expires_in * 1000),
				accessTokenExpiresInSeconds: data.expires_in,
				idToken: data.id_token ? this.parseIdToken(data.id_token) : null,
				refreshToken: data.refresh_token ?? null,
				scopes: data.scope.split(" "),
				sessionId: this.generateSessionId(token),
				state: null,
				token,
				tokenType: data.token_type,
			};
		},
		this.onError,
	);

	/**
	 * Acquires a token using the client credentials flow for a specified application.
	 * Uses the configured defaultScope. Intended to be used for service-to-service
	 * authentication where no user context is required.
	 *
	 * @param applicationId - The client ID of the application for which to acquire the token.
	 * @returns A promise that resolves to a Result containing either the acquired token or an error.
	 */
	acquireTokenByClientCredential = tryCatch(
		async (applicationId: keyof Config) => {
			const body = new URLSearchParams({
				client_id: this.clientId,
				client_secret: this.clientSecret,
				grant_type: "client_credentials",
				scope: this.oboApplications[applicationId].defaultScope,
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
						applicationId,
					},
				});
			}

			return defaultTokenSchema.parse(await response.json());
		},
		this.onError,
	);
}

export * from "./error-handling";
export * from "./lib/zod";
export * from "./types";
