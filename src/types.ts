export type Session = {
	id: string;
	accessToken: string;
	refreshToken: string | null;
	tokenType: string;
	expiresOn: Date | null;
	scopes: string | null;
	state: string | null;
};

export type User = {
	id: string;
	name: string | null;
	email: string;
	department: string | null;
	roles: string | null;
	keystoneInitials: string | null;
	dateCreated: Date;
	dateUpdated: Date | null;
};

export type OboApplicationConfig = {
	[clientId: string]: {
		scopes: string[];
	};
};

export interface IAuthProviderProps<Config extends OboApplicationConfig> {
	readonly clientId: string;
	readonly tenantId: string;
	readonly clientSecret: string;
	readonly redirectUri: string;
	readonly scopes: string[];
	readonly timeout?: number;
	onError?: <T extends Error>(error: T) => void | Promise<void>;
	oboApplications: Config;
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
