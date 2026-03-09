import { AuthProvider } from "./";
import type {
	DeleteSessionProps,
	GetOboSessionProps,
	GetSessionProps,
	ISessionProvider,
	RefreshSessionProps,
	SessionProviderCallbacks,
	SessionProviderProps,
} from "./types";

export class SessionProvider<State = unknown>
	extends AuthProvider
	implements ISessionProvider<State>
{
	private readonly sessionCallbacks: SessionProviderCallbacks<State>;

	constructor({ sessionCallbacks, ...rest }: SessionProviderProps<State>) {
		super({ ...rest });

		this.sessionCallbacks = sessionCallbacks;
	}

	private async refresh({
		refreshToken,
		scopes,
		readonlyCookies = true,
		state,
	}: RefreshSessionProps<State>) {
		const { data } = await this.refreshAccessToken({ refreshToken, scopes });
		if (!data) {
			return null;
		}

		if (!readonlyCookies) {
			await this.sessionCallbacks.insert({ authTokens: data, scopes, state });
		}

		return data;
	}

	/**
	 * Delete the session.
	 */
	async delete({ token, sessionId, state }: DeleteSessionProps<State>) {
		await this.sessionCallbacks.delete({
			sessionId: sessionId ?? this.generateSessionId(token),
			state,
		});
	}

	/**
	 * Can be used for any application.
	 */
	async get({
		token,
		scopes,
		readonlyCookies = true,
		state,
	}: GetSessionProps<State>) {
		const sessionId = this.generateSessionId(token);
		const session = await this.sessionCallbacks.select({
			sessionId,
			token,
			state,
		});
		if (!session) {
			return null;
		}

		if (Date.now() >= session.oauth2Tokens.accessTokenExpiresAt().getTime()) {
			await this.delete({ sessionId, state });
			if (!session.oauth2Tokens.hasRefreshToken()) {
				return null;
			}
			return this.refresh({
				refreshToken: session.oauth2Tokens.refreshToken(),
				scopes,
				readonlyCookies,
				state,
			});
		}

		return session;
	}

	/**
	 * Should be used strictly for obo tokens. Don't use it for regular tokens.
	 */
	async getObo({
		token,
		scopes,
		oboToken,
		oboScopes,
		readonlyCookies = true,
		state,
	}: GetOboSessionProps<State>) {
		const oboSession = await this.get({
			token: oboToken,
			scopes: oboScopes,
			readonlyCookies,
			state,
		});
		if (oboSession) {
			return oboSession;
		}

		const session = await this.get({ scopes, token, readonlyCookies, state });
		if (!session) {
			return null;
		}

		const { data } = await this.acquireTokenOnBehalfOf({
			accessToken: session.oauth2Tokens.accessToken(),
			scopes: oboScopes,
		});
		if (!data) {
			await this.delete({ token: oboToken, state });
			return null;
		}

		if (!readonlyCookies) {
			await this.sessionCallbacks.insert({
				authTokens: data,
				scopes: oboScopes,
				state,
			});
		}

		return data;
	}
}
