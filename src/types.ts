import type { ZodObject } from "zod";
import type { BaseIdToken, baseIdTokenSchema } from "./lib/zod";

export type OboApplicationConfig = {
	[clientId: string]: {
		defaultScope: string;
		scopes: string[];
	};
};

export interface IAuthProviderProps<
	Config extends OboApplicationConfig,
	Schema extends ZodObject<typeof baseIdTokenSchema.shape>,
> {
	readonly clientId: string;
	readonly tenantId: string;
	readonly clientSecret: string;
	readonly redirectUri: string;
	readonly scopes: string[];
	readonly timeout?: number;
	onError?: <T extends Error>(error: T) => void | Promise<void>;
	oboApplications: Config;
	readonly idTokenSchema: Schema;
}

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

export type AuthTokens<IdToken extends BaseIdToken> = {
	accessToken: string;
	accessTokenExpiresAt: Date;
	accessTokenExpiresInSeconds: number;
	idToken: IdToken | null;
	refreshToken: string | null;
	scopes: string[];
	sessionId: string;
	state: string | null;
	token: string;
	tokenType: string;
};
