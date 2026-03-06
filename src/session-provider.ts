import { AuthProvider } from "./";
import type {
  AuthProviderCallbacks,
  AuthProviderProps,
  AuthProviderResponse,
  IAuthProvider,
  GetSessionProps,
  GetOboSessionProps,
  RefreshSessionProps,
} from "./types";

interface SessionProviderCallbacks extends AuthProviderCallbacks {
  selectSession: (sessionId: string) => Promise<AuthProviderResponse | null>;
  deleteSession: (sessionId: string) => Promise<void>;
  updateSession: (
    sessionId: string,
    authTokens: AuthProviderResponse,
  ) => Promise<void>;
  insertSession: (authTokens: AuthProviderResponse) => Promise<void>;
  onNoSession?: () => never;
}

type DeleteSessionProps =
  | { token: string; sessionId?: undefined }
  | { token?: undefined; sessionId: string };

interface SessionProviderProps extends AuthProviderProps {
  readonly callbacks: SessionProviderCallbacks;
}

interface ISessionProvider extends IAuthProvider {
  delete: (props: DeleteSessionProps) => Promise<void>;
  get: (token: string, readonlyCookies?: boolean) => Promise<void>;
}

export class SessionProvider extends AuthProvider {
  protected readonly callbacks: SessionProviderCallbacks;

  constructor({ callbacks, ...rest }: SessionProviderProps) {
    const authProviderCallbacks = callbacks.onError && {
      onError: callbacks.onError,
    };
    super({ ...rest, callbacks: authProviderCallbacks });

    this.callbacks = callbacks;
  }

  private shouldTokenRefresh(expiresOn: Date | null) {
    return !expiresOn || Date.now() <= expiresOn.getTime();
  }

  private async refresh({
    refreshToken,
    scopes,
    readonlyCookies = true,
  }: RefreshSessionProps) {
    const { data } = await this.refreshAccessToken(refreshToken, scopes);
    if (!data) {
      this.callbacks.onNoSession?.();
      return null;
    }

    if (!readonlyCookies) {
      await this.callbacks.insertSession(data);
    }

    return data;
  }

  async delete({ token, sessionId }: DeleteSessionProps) {
    await this.callbacks.deleteSession(
      sessionId ?? this.generateSessionId(token),
    );
  }

  async get({ token, scopes, readonlyCookies = true }: GetSessionProps) {
    const sessionId = this.generateSessionId(token);
    const session = await this.callbacks.selectSession(sessionId);
    if (!session) {
      this.callbacks.onNoSession?.();
      return null;
    }

    if (!this.shouldTokenRefresh(session.oauth2Tokens.accessTokenExpiresAt())) {
      return session;
    }

    if (session.oauth2Tokens.hasRefreshToken()) {
      return this.refresh({
        refreshToken: session.oauth2Tokens.refreshToken(),
        scopes,
        readonlyCookies,
      });
    }

    await this.delete({ sessionId });
    this.callbacks.onNoSession?.();
    return null;
  }

  private async getOboFlow({
    oboScopes,
    oboToken,
    scopes,
    token,
    readonlyCookies,
  }: GetOboSessionProps) {}

  async getObo({
    token,
    scopes,
    oboToken,
    oboScopes,
    readonlyCookies = true,
  }: GetOboSessionProps) {
    const oboSessionId = this.generateSessionId(oboToken);
    const oboSession = await this.callbacks.selectSession(oboSessionId);

    if (!oboSession) {
      let session = await this.get({ scopes, token, readonlyCookies });
      if (!session) {
        this.callbacks.onNoSession?.();
        return null;
      }

      // TODO: check session to see if it has expired. if it has attempt refresh.

      const { data } = await this.acquireTokenOnBehalfOf(
        session.oauth2Tokens.accessToken(),
        oboScopes,
      );
      if (!data) {
        await this.delete({ sessionId: oboSessionId });
        this.callbacks.onNoSession?.();
        return null;
      }
      return data;
    }

    if (
      !this.shouldTokenRefresh(oboSession.oauth2Tokens.accessTokenExpiresAt())
    ) {
      return oboSession;
    }

    if (oboSession.oauth2Tokens.hasRefreshToken()) {
      const newObosession = this.refresh({
        refreshToken: oboSession.oauth2Tokens.refreshToken(),
        scopes: oboScopes,
        readonlyCookies,
      });
      if (!newObosession) {
        // TODO: attempt obo exchange
      }
    }

    await this.delete({ sessionId: oboSessionId });
    this.callbacks.onNoSession?.();
    return null;
  }
}
