import { sha256 } from "@oslojs/crypto/sha2";
import { encodeBase32, encodeHexLowerCase } from "@oslojs/encoding";
import {
	decodeIdToken,
	generateCodeVerifier,
	generateState,
	MicrosoftEntraId,
	type OAuth2Tokens,
} from "arctic";
import { FetchError, tryCatch, tryCatchSync } from "./error-handling";
import { defaultTokenSchema, idTokenSchema, oboTokenSchema } from "./lib/zod";
import type { Session, User } from "./types";

type AuthProviderConfig = {
	tenantId: string;
	clientId: string;
	clientSecret: string;
	redirect: string;
};

export class AuthProvider {
	private readonly entraId: MicrosoftEntraId;
	private readonly clientId: string;
	private readonly clientSecret: string;
	private readonly microsoftOAuthUrl: string;

	constructor(config: AuthProviderConfig) {
		const { clientId, clientSecret, tenantId, redirect } = config;

		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.microsoftOAuthUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

		this.entraId = new MicrosoftEntraId(
			tenantId,
			clientId,
			clientSecret,
			redirect,
		);
	}

	refreshAccessToken = tryCatch(
		async (refreshToken: string, scopes: string[], state?: string) => {
			const tokens = await this.entraId.refreshAccessToken(
				refreshToken,
				scopes,
			);

			return this.formatSessionTokenAndUser(tokens, state);
		},
	);

	validateAuthorizationCode = tryCatch(
		async (code: string, codeVerifier: string, state: string) => {
			const tokens = await this.entraId.validateAuthorizationCode(
				code,
				codeVerifier,
			);
			const idToken = tokens.idToken();

			const { data: user } = this.userFromIdToken(idToken);
			if (!user) {
				throw new Error("validateAuthorizationCode", {
					cause: JSON.stringify({ code, codeVerifier, state }),
				});
			}

			const token = this.generateSessionToken();
			const sessionId = this.generateSessionId(token);
			const session = {
				id: sessionId,
				accessToken: tokens.accessToken(),
				expiresOn: tokens.accessTokenExpiresAt(),
				userId: user.id,
				refreshToken: tokens.refreshToken(),
				scopes: tokens.scopes().join(" "),
				tokenType: tokens.tokenType(),
				state,
			};

			return { token, session, user };
		},
	);

	createAuthorizationURL(scope: string[]) {
		const state = generateState();
		const codeVerifier = generateCodeVerifier();

		const url = this.entraId.createAuthorizationURL(state, codeVerifier, scope);
		url.searchParams.set("nonce", codeVerifier);

		return { url, state, codeVerifier };
	}

	userFromIdToken = tryCatchSync((idToken: string) => {
		const decodedIdToken = idTokenSchema.parse(decodeIdToken(idToken));

		const user: User = {
			email: decodedIdToken.email,
			id: decodedIdToken.oid,
			name: decodedIdToken.name,
			roles: decodedIdToken.roles?.join(" ") ?? null,
			dateCreated: new Date(),
			dateUpdated: null,
			department: null,
			keystoneInitials: null,
		};

		return user;
	});

	formatSessionTokenAndUser(tokens: OAuth2Tokens, state?: string) {
		const idToken = tokens.idToken();

		const { data: user } = this.userFromIdToken(idToken);
		if (!user) return null;

		const token = this.generateSessionToken();
		const sessionId = this.generateSessionId(token);

		const session: Session = {
			id: sessionId,
			accessToken: tokens.accessToken(),
			expiresOn: tokens.accessTokenExpiresAt(),
			userId: user.id,
			refreshToken: tokens.refreshToken(),
			scopes: tokens.scopes().join(" "),
			tokenType: tokens.tokenType(),
			state: state ?? null,
		};

		return { session, user, token };
	}

	generateSessionToken() {
		const tokenBytes = new Uint8Array(20);
		crypto.getRandomValues(tokenBytes);
		const token = encodeBase32(tokenBytes).toLowerCase();
		return token;
	}

	generateSessionId(token: string) {
		return encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	}

	tokenToSessionId(token: string) {
		return encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	}

	acquireTokenOnBehalfOf = tryCatch(
		async (accessToken: string, scopes: string[]) => {
			const body = new URLSearchParams({
				grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
				client_id: this.clientId,
				client_secret: this.clientSecret,
				assertion: accessToken,
				scope: scopes.join(" "),
				requested_token_use: "on_behalf_of",
			});

			const response = await fetch(this.microsoftOAuthUrl, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body,
			});
			if (!response.ok) {
				const error = new FetchError(
					response,
					"On Behalf Of OAuth Flow",
					await response.text(),
				);
				throw error;
			}

			const data = oboTokenSchema.parse(await response.json());

			const token = this.generateSessionToken();
			const sessionId = this.generateSessionId(token);
			const session = {
				id: sessionId,
				accessToken: data.access_token,
				tokenType: data.token_type,
				expiresOn: new Date(Date.now() + data.expires_in * 1000),
				scopes: data.scope,
				refreshToken: data.refresh_token,
			};

			return { session, token };
		},
	);

	acquireTokenByClientCredential = tryCatch(async (scopes: string[]) => {
		const body = new URLSearchParams({
			client_id: this.clientId,
			client_secret: this.clientSecret,
			grant_type: "client_credentials",
			scope: scopes.join(" "),
		});

		const response = await fetch(this.microsoftOAuthUrl, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body,
		});

		if (!response.ok) {
			const error = new FetchError(
				response,
				"Acquiring Token By Client Credentials Failed",
				await response.text(),
			);
			throw error;
		}

		return defaultTokenSchema.parse(await response.json());
	});
}
