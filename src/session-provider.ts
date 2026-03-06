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

export class SessionProvider extends AuthProvider implements ISessionProvider {
	private readonly sessionCallbacks: SessionProviderCallbacks;

	constructor({ sessionCallbacks, ...rest }: SessionProviderProps) {
		super({ ...rest });

		this.sessionCallbacks = sessionCallbacks;
	}

	private async refresh({
		refreshToken,
		scopes,
		readonlyCookies = true,
	}: RefreshSessionProps) {
		const { data } = await this.refreshAccessToken({ refreshToken, scopes });
		if (!data) {
			return null;
		}

		if (!readonlyCookies) {
			await this.sessionCallbacks.insertSession(data);
		}

		return data;
	}

	/**
	 * Delete the session.
	 */
	async delete({ token, sessionId }: DeleteSessionProps) {
		await this.sessionCallbacks.deleteSession(
			sessionId ?? this.generateSessionId(token),
		);
	}

	/**
	 * Can be used for any application.
	 */
	async get({ token, scopes, readonlyCookies = true }: GetSessionProps) {
		const sessionId = this.generateSessionId(token);
		const session = await this.sessionCallbacks.selectSession(sessionId);
		if (!session) {
			return null;
		}

		if (Date.now() >= session.oauth2Tokens.accessTokenExpiresAt().getTime()) {
			await this.delete({ sessionId });
			if (session.oauth2Tokens.hasRefreshToken()) {
				return null;
			}
			return this.refresh({
				refreshToken: session.oauth2Tokens.refreshToken(),
				scopes,
				readonlyCookies,
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
	}: GetOboSessionProps) {
		const oboSession = await this.get({
			token: oboToken,
			scopes: oboScopes,
			readonlyCookies,
		});
		if (oboSession) {
			return oboSession;
		}

		const session = await this.get({ scopes, token, readonlyCookies });
		if (!session) {
			return null;
		}

		const { data } = await this.acquireTokenOnBehalfOf({
			accessToken: session.oauth2Tokens.accessToken(),
			scopes: oboScopes,
		});
		if (!data) {
			await this.delete({ token: oboToken });
			return null;
		}

		if (!readonlyCookies) {
			await this.sessionCallbacks.insertSession(data);
		}

		return data;
	}
}
