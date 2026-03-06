import type { OAuth2Tokens } from "arctic";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SessionProvider } from "../src/index";
import type {
	AuthProviderResponse,
	InsertSessionProps,
	SelectSessionProps,
} from "../src/types";

vi.mock("arctic");

const createMockOAuth2Tokens = (expiresAt?: Date): OAuth2Tokens => {
	const expiry = expiresAt ?? new Date(Date.now() + 3600 * 1000);
	return {
		accessToken: () => "mock-access-token",
		refreshToken: () => "mock-refresh-token",
		idToken: () => "mock-id-token",
		accessTokenExpiresAt: () => expiry,
		accessTokenExpiresInSeconds: () => 3600,
		hasRefreshToken: () => true,
		hasScopes: () => true,
		scopes: () => ["openid", "profile", "email"],
		tokenType: () => "Bearer",
		data: {
			id_token: "mock-id-token",
		},
	} as OAuth2Tokens;
};

const createMockSession = (expiresAt?: Date): AuthProviderResponse => {
	const oauth2Tokens = createMockOAuth2Tokens(expiresAt);
	return {
		token: "mock-session-token",
		sessionId: "mock-session-id",
		oauth2Tokens,
	};
};

const createTestSessionProvider = (
	overrides?: Partial<{
		timeout?: number;
		onError?: (error: Error) => void | Promise<void>;
	}>,
	callbacks?: {
		select?: (
			props: SelectSessionProps,
		) => Promise<AuthProviderResponse | null>;
		delete?: (sessionId: string) => Promise<void>;
		insert?: (props: InsertSessionProps) => Promise<void>;
	},
) => {
	return new SessionProvider({
		clientId: "test-client-id",
		clientSecret: "test-client-secret",
		tenantId: "test-tenant-id",
		redirectUri: "http://localhost:3000/callback",
		sessionCallbacks: {
			select: async () => null,
			delete: async () => {},
			insert: async () => {},
			...callbacks,
		},
		...overrides,
	});
};

describe("SessionProvider", () => {
	describe("Constructor", () => {
		it("should initialize with valid config", () => {
			const provider = createTestSessionProvider();

			expect(provider.clientId).toBe("test-client-id");
			expect(provider.tenantId).toBe("test-tenant-id");
			expect(provider.redirectUri).toBe("http://localhost:3000/callback");
		});

		it("should set timeout if provided", () => {
			const provider = createTestSessionProvider({ timeout: 5000 });

			expect(provider.timeout).toBe(5000);
		});
	});

	describe("get", () => {
		beforeEach(() => {
			vi.useFakeTimers();
		});

		afterEach(() => {
			vi.useRealTimers();
			vi.clearAllMocks();
		});

		it("should return session when token is valid and not expired", async () => {
			const mockSession = createMockSession();
			const provider = createTestSessionProvider(undefined, {
				select: async () => mockSession,
			});

			const result = await provider.get({
				token: "test-token",
				scopes: ["openid", "profile"],
			});

			expect(result).not.toBeNull();
			expect(result?.token).toBe("mock-session-token");
		});

		it("should return null when session does not exist", async () => {
			const provider = createTestSessionProvider(undefined, {
				select: async () => null,
			});

			const result = await provider.get({
				token: "nonexistent-token",
				scopes: ["openid", "profile"],
			});

			expect(result).toBeNull();
		});

		it("should refresh token when expired and has refresh token", async () => {
			const expiredSession = createMockSession(new Date(Date.now() - 1000));
			const refreshedSession = createMockSession();

			const provider = createTestSessionProvider(undefined, {
				select: async () => expiredSession,
			});

			vi.spyOn(provider, "refreshAccessToken").mockResolvedValue({
				data: refreshedSession,
				error: null,
			});

			const result = await provider.get({
				token: "test-token",
				scopes: ["openid", "profile"],
			});

			expect(result).not.toBeNull();
			expect(result?.token).toBe("mock-session-token");
		});

		it("should delete session and return null when expired but no refresh token", async () => {
			const expiredSessionWithoutRefresh: AuthProviderResponse = {
				token: "mock-session-token",
				sessionId: "mock-session-id",
				oauth2Tokens: {
					accessToken: () => "mock-access-token",
					refreshToken: () => "",
					idToken: () => "mock-id-token",
					accessTokenExpiresAt: () => new Date(Date.now() - 1000),
					accessTokenExpiresInSeconds: () => 0,
					hasRefreshToken: () => false,
					hasScopes: () => true,
					scopes: () => ["openid", "profile", "email"],
					tokenType: () => "Bearer",
					data: {},
				} as OAuth2Tokens,
			};

			const deleteSessionSpy = vi.fn();
			const provider = createTestSessionProvider(undefined, {
				select: async () => expiredSessionWithoutRefresh,
				delete: deleteSessionSpy,
			});

			const result = await provider.get({
				token: "test-token",
				scopes: ["openid", "profile"],
			});

			expect(deleteSessionSpy).toHaveBeenCalledWith(
				provider.generateSessionId("test-token"),
			);
			expect(result).toBeNull();
		});

		it("should save new session when readonlyCookies is false", async () => {
			const expiredSession = createMockSession(new Date(Date.now() - 1000));
			const refreshedSession = createMockSession();

			const insertSessionSpy = vi.fn(async (props: InsertSessionProps) => {});
			const provider = createTestSessionProvider(undefined, {
				select: async () => expiredSession,
				insert: insertSessionSpy,
			});

			vi.spyOn(provider, "refreshAccessToken").mockResolvedValue({
				data: refreshedSession,
				error: null,
			});

			const result = await provider.get({
				token: "test-token",
				scopes: ["openid", "profile"],
				readonlyCookies: false,
			});

			expect(insertSessionSpy).toHaveBeenCalledWith({
				authTokens: refreshedSession,
				scopes: ["openid", "profile"],
			});
			expect(result).not.toBeNull();
		});
	});

	describe("getObo", () => {
		beforeEach(() => {
			vi.useFakeTimers();
		});

		afterEach(() => {
			vi.useRealTimers();
			vi.clearAllMocks();
		});

		it("should return existing OBO session when valid", async () => {
			const oboSession = createMockSession();
			const provider = createTestSessionProvider(undefined, {
				select: async () => oboSession,
			});

			const result = await provider.getObo({
				token: "main-token",
				scopes: ["openid", "profile"],
				oboToken: "obo-token",
				oboScopes: ["https://graph.microsoft.com/.default"],
			});

			expect(result).not.toBeNull();
			expect(result?.token).toBe("mock-session-token");
		});

		it("should return null when OBO session does not exist and main session also does not exist", async () => {
			const provider = createTestSessionProvider(undefined, {
				select: async () => null,
			});

			const result = await provider.getObo({
				token: "main-token",
				scopes: ["openid", "profile"],
				oboToken: "obo-token",
				oboScopes: ["https://graph.microsoft.com/.default"],
			});

			expect(result).toBeNull();
		});
	});

	describe("delete", () => {
		beforeEach(() => {
			vi.useFakeTimers();
		});

		afterEach(() => {
			vi.useRealTimers();
			vi.clearAllMocks();
		});

		it("should call deleteSession with generated sessionId when only token provided", async () => {
			const deleteSessionSpy = vi.fn();
			const provider = createTestSessionProvider(undefined, {
				delete: deleteSessionSpy,
			});

			await provider.delete({ token: "test-token" });

			expect(deleteSessionSpy).toHaveBeenCalledWith(
				provider.generateSessionId("test-token"),
			);
		});

		it("should call deleteSession with provided sessionId", async () => {
			const deleteSessionSpy = vi.fn();
			const provider = createTestSessionProvider(undefined, {
				delete: deleteSessionSpy,
			});

			await provider.delete({ sessionId: "custom-session-id" });

			expect(deleteSessionSpy).toHaveBeenCalledWith("custom-session-id");
		});
	});
});
