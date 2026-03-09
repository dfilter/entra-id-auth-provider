import type { OAuth2Tokens } from "arctic";

type Success<T> = {
	data: T;
	error: null;
};

type Failure<E> = {
	data: null;
	error: E;
};

export type Result<T, E = Error> = Success<T> | Failure<E>;

export interface ErrorProps {
	message: string;
	body: string;
	status: number;
	statusText: string;
	props: Record<string, any>;
}

export type OAuth2TokensProps = {
	token_type: string;
	access_token: string;
	expires_in: number;
	refresh_token?: string;
	scope?: string;
	id_token?: string;
};

export type AuthProviderCallbacks = {
	onError?: (error: Error) => Promise<void> | void;
};

export type AuthProviderResponse = {
	token: string;
	sessionId: string;
	oauth2Tokens: OAuth2Tokens;
};

export type AuthProviderResult = Result<AuthProviderResponse>;

export type AuthorizationUrl = {
	url: URL;
	state: string;
	codeVerifier: string;
};

export interface AuthProviderProps {
	readonly clientId: string;
	readonly tenantId: string;
	readonly clientSecret: string;
	readonly redirectUri: string;
	readonly timeout?: number;
	readonly callbacks?: AuthProviderCallbacks;
}

export type ValidateAuthorizationCodeProps = {
	code: string;
	codeVerifier: string;
};

export type AcquireTokenOnBehalfOfProps = {
	accessToken: string;
	scopes: string[];
};

export type RefreshAccessTokenProps = {
	refreshToken: string;
	scopes: string[];
	state?: string;
};

export interface IAuthProvider
	extends Omit<AuthProviderProps, "clientSecret" | "callbacks"> {
	decodeIdToken: (idToken: string) => Result<object, Error>;
	refreshAccessToken: (
		props: RefreshAccessTokenProps,
	) => Promise<AuthProviderResult>;
	validateAuthorizationCode: (
		props: ValidateAuthorizationCodeProps,
	) => Promise<AuthProviderResult>;
	createAuthorizationURL(scopes: string[]): AuthorizationUrl;
	generateSessionToken(): string;
	generateSessionId(token: string): string;
	acquireTokenOnBehalfOf: (
		props: AcquireTokenOnBehalfOfProps,
	) => Promise<AuthProviderResult>;
	acquireTokenByClientCredential: (
		scopes: string[],
	) => Promise<AuthProviderResult>;
}

export type AuthApplication = {
	readonly name: string;
	readonly defaultScope: string;
	readonly scopes: string[];
	readonly cookieName: string;
};

export type GetSessionProps<State> = {
	token: string;
	scopes: string[];
	readonlyCookies?: boolean;
	state: State;
};

export interface GetOboSessionProps<State> extends GetSessionProps<State> {
	oboToken: string;
	oboScopes: string[];
}

export type RefreshSessionProps<State> = {
	refreshToken: string;
	scopes: string[];
	readonlyCookies?: boolean;
	state: State;
};

export type SelectSessionProps<State> = {
	token: string;
	sessionId: string;
	state: State;
};

export type InsertSessionProps<State> = {
	authTokens: AuthProviderResponse;
	scopes: string[];
	state: State;
};

export interface SessionProviderCallbacks<State> {
	select: (
		props: SelectSessionProps<State>,
	) => Promise<AuthProviderResponse | null>;
	delete: (props: { sessionId: string; state: State }) => Promise<void>;
	insert: (props: InsertSessionProps<State>) => Promise<void>;
}

export type DeleteSessionProps<State> =
	| { token: string; sessionId?: undefined; state: State }
	| { token?: undefined; sessionId: string; state: State };

export interface SessionProviderProps<State> extends AuthProviderProps {
	readonly sessionCallbacks: SessionProviderCallbacks<State>;
}

export interface ISessionProvider<State> extends IAuthProvider {
	delete: (props: DeleteSessionProps<State>, state: State) => Promise<void>;
	get: (props: GetSessionProps<State>) => Promise<AuthProviderResponse | null>;
	getObo: (
		props: GetOboSessionProps<State>,
	) => Promise<AuthProviderResponse | null>;
}
