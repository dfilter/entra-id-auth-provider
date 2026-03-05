import type {
	AuthProvider,
	AuthTokens,
	OboApplicationConfig,
} from "entra-id-auth-provider";
import type { ZodObject, z } from "zod";
import { authProvider } from "@/lib/oauth/auth";
import type { idTokenSchema } from "@/lib/oauth/helpers";

type SessionProviderCallbacks<AuthTokens> = {
	selectSession: (sessionId: string) => Promise<AuthTokens | null>;
	deleteSession: (sessionId: string) => Promise<void>;
	updateSession: (sessionId: string, authTokens: AuthTokens) => Promise<void>;
	insertSession: (authTokens: AuthTokens) => Promise<void>;
	getSessionCookie: (name: string) => string | null;
	setSessionCookie: (name: string) => void;
	deleteSessionCookie: (name: string) => void;
	onNoSession?: () => never;
};

type OBOApplicationCookies = {
	[applicationId: string]: string;
};

type DeleteProps<T extends OBOApplicationCookies> = {
	sessionId: string;
	applicationId?: keyof T;
	readonlyCookies?: boolean;
};

interface ISessionProvider<
	Config extends OboApplicationConfig,
	Schema extends ZodObject<typeof idTokenSchema.shape>,
> {
	readonly authProvider: AuthProvider<Config, Schema>;
	readonly callbacks: SessionProviderCallbacks<AuthTokens<z.infer<Schema>>>;
	readonly cookie: string;
	readonly oboApplicationCookies: OBOApplicationCookies;
	get: (
		readonlyCookies?: boolean,
	) => Promise<AuthTokens<z.infer<Schema>> | null>;
	delete: (props: DeleteProps<OBOApplicationCookies>) => Promise<void>;
}

export class SessionProvider<
	Config extends OboApplicationConfig,
	Schema extends ZodObject<typeof idTokenSchema.shape>,
> implements ISessionProvider<Config, Schema>
{
	readonly authProvider: AuthProvider<Config, Schema>;
	readonly callbacks: SessionProviderCallbacks<
		AuthTokens<z.infer<typeof this.authProvider.idTokenSchema>>
	>;
	readonly cookie: string;
	readonly oboApplicationCookies: OBOApplicationCookies;

	constructor({
		authProvider,
		callbacks,
		cookie,
		oboApplicationCookies,
	}: ISessionProvider<Config, Schema>) {
		this.authProvider = authProvider;
		this.callbacks = callbacks;
		this.cookie = cookie;
		this.oboApplicationCookies = oboApplicationCookies;
	}

	private shouldTokenRefresh(
		expiresOn: Date | null,
		gracePeriod = 900000 /* fifteen minutes */,
	) {
		return (
			expiresOn &&
			(Date.now() >= expiresOn.getTime() - gracePeriod ||
				expiresOn.getTime() <= Date.now())
		);
	}

	async delete({
		sessionId,
		applicationId,
		readonlyCookies = true,
	}: DeleteProps<OBOApplicationCookies>) {
		await this.callbacks.deleteSession(sessionId);
		if (!readonlyCookies) {
			const cookie = applicationId
				? this.oboApplicationCookies[applicationId]
				: this.cookie;
			this.callbacks.deleteSessionCookie(cookie);
		}
	}

	async get(
		readonlyCookies = true,
	): Promise<AuthTokens<
		z.infer<typeof this.authProvider.idTokenSchema>
	> | null> {
		const token = this.callbacks.getSessionCookie(this.cookie);
		if (!token) {
			this.callbacks.onNoSession?.();
			return null;
		}

		const sessionId = this.authProvider.generateSessionId(token);
		const session = await this.callbacks.selectSession(sessionId);
		if (!session) {
			this.callbacks.onNoSession?.();
			return null;
		}

		if (!this.shouldTokenRefresh(session.accessTokenExpiresAt)) {
			return session;
		}

		if (!session.refreshToken) {
			await this.delete({ sessionId: session.sessionId, readonlyCookies });
			this.callbacks.onNoSession?.();
			return null;
		}

		const { data } = await this.authProvider.refreshAccessToken(
			session.refreshToken,
		);
		if (!data) {
			this.callbacks.onNoSession?.();
			return null;
		}

		if (!readonlyCookies) {
			await this.callbacks.insertSession(data);
			this.callbacks.setSessionCookie(this.cookie);
		}

		return data;
	}

	private async getOboSession(
		applicationId: keyof OBOApplicationCookies,
		skipCookies = true,
	) {}

	async getApplicationSession(
		applicationId: keyof OBOApplicationCookies,
		skipCookies = true,
	) {
		const token = this.callbacks.getSessionCookie(
			this.oboApplicationCookies[applicationId],
		);
		if (!token) {
			// TODO: do OBO flow
			// const {} = await this.authProvider.acquireTokenOnBehalfOf
			return null;
		}

		const sessionId = this.authProvider.generateSessionId(token);
		const session = await this.callbacks.selectSession(sessionId);

		if (!session) {
			// TODO: do OBO flow
			return null;
		}

		if (!this.shouldTokenRefresh(session.accessTokenExpiresAt)) {
			return session;
		}

		// TODO: refresh the OBO token
	}
}

const sessionProvider = new SessionProvider({
	authProvider,
	callbacks: {
		deleteSession(sessionId) {},
		deleteSessionCookie(name) {},
		getSessionCookie(name) {},
		insertSession(newSession) {},
		selectSession(sessionId) {},
		setSessionCookie(name) {},
		updateSession(sessionId, sessionUpdate) {},
		onNoSession() {},
	},
	cookie: "tasked_session",
	oboApplicationCookies: {
		CONTACTS_API: "tasked_contacts_api_token",
	},
});

sessionProvider.getApplicationSession("");
