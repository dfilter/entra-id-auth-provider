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

export interface IAuthProvider
  extends Omit<AuthProviderProps, "clientSecret" | "callbacks"> {
  decodeIdToken: (idToken: string) => Result<object, Error>;
  refreshAccessToken: (
    refreshToken: string,
    scopes: string[],
    state?: string,
  ) => Promise<AuthProviderResult>;
  validateAuthorizationCode: (
    code: string,
    codeVerifier: string,
    state: string,
  ) => Promise<AuthProviderResult>;
  createAuthorizationURL(scopes: string[]): AuthorizationUrl;
  generateSessionToken(): string;
  generateSessionId(token: string): string;
  acquireTokenOnBehalfOf: (
    accessToken: string,
    scopes: string[],
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

export type GetSessionProps = {
  token: string;
  scopes: string[];
  readonlyCookies?: boolean;
};

export interface GetOboSessionProps extends GetSessionProps {
  oboToken: string;
  oboScopes: string[];
}

export type RefreshSessionProps = {
  refreshToken: string;
  scopes: string[];
  readonlyCookies?: boolean;
};
