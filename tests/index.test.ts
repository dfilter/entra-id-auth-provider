import type { OAuth2Tokens } from "arctic";
import { decodeIdToken, generateCodeVerifier, generateState } from "arctic";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	AcquireTokenByClientCredentialError,
	AcquireTokenOnBehalfOfError,
} from "../src/error-handling";
import { AuthProvider } from "../src/index";

vi.mock("arctic");

const createMockOAuth2Tokens = (): OAuth2Tokens => {
	return {
		accessToken: () => "mock-access-token",
		refreshToken: () => "mock-refresh-token",
		idToken: () => "mock-id-token",
		accessTokenExpiresAt: () => new Date(Date.now() + 3600 * 1000),
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

const createTestProvider = (
	overrides?: Partial<{
		timeout?: number;
		onError?: (error: Error) => void | Promise<void>;
	}>,
) => {
	return new AuthProvider({
		clientId: "test-client-id",
		clientSecret: "test-client-secret",
		tenantId: "test-tenant-id",
		redirectUri: "http://localhost:3000/callback",
		...overrides,
	});
};

beforeEach(() => {
	vi.clearAllMocks();
	vi.mocked(generateState).mockReturnValue("mock-state");
	vi.mocked(generateCodeVerifier).mockReturnValue("mock-codeverifier");
	vi.spyOn(Math, "random").mockImplementation(() => 0.5);
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("AuthProvider", () => {
	describe("Constructor", () => {
		it("should initialize with valid config", () => {
			const provider = createTestProvider();

			expect(provider.clientId).toBe("test-client-id");
			expect(provider.tenantId).toBe("test-tenant-id");
			expect(provider.redirectUri).toBe("http://localhost:3000/callback");
		});

		it("should set correct Microsoft OAuth URL", () => {
			const provider = createTestProvider();

			expect(provider.microsoftOAuthUrl).toBe(
				"https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token",
			);
		});

		it("should set timeout if provided", () => {
			const provider = createTestProvider({ timeout: 5000 });

			expect(provider.timeout).toBe(5000);
		});
	});

	describe("createAuthorizationURL", () => {
		it("should return URL with state and codeVerifier", () => {
			const provider = createTestProvider();
			vi.mocked(provider.entraId.createAuthorizationURL).mockReturnValue(
				new URL(
					"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
				),
			);

			const { url, state, codeVerifier } = provider.createAuthorizationURL([]);

			expect(url).toBeInstanceOf(URL);
			expect(state).toBe("mock-state");
			expect(codeVerifier).toBe("mock-codeverifier");
		});

		it("should include nonce parameter", () => {
			const provider = createTestProvider();
			vi.mocked(provider.entraId.createAuthorizationURL).mockReturnValue(
				new URL(
					"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
				),
			);

			const { url } = provider.createAuthorizationURL([]);

			expect(url.searchParams.get("nonce")).toBe("mock-codeverifier");
		});
	});

	describe("generateSessionToken", () => {
		it("should generate unique tokens", () => {
			const provider = createTestProvider();
			const token1 = provider.generateSessionToken();
			const token2 = provider.generateSessionToken();

			expect(token1).not.toBe(token2);
		});

		it("should generate base32 lowercase encoded tokens", () => {
			const provider = createTestProvider();
			const token = provider.generateSessionToken();

			expect(token).toMatch(/^[a-z2-9]+=*$/i);
		});
	});

	describe("generateSessionId", () => {
		it("should return consistent SHA256 hash", () => {
			const provider = createTestProvider();
			const token = "test-token";
			const sessionId = provider.generateSessionId(token);

			expect(sessionId).toHaveLength(64);
			expect(provider.generateSessionId(token)).toBe(sessionId);
		});
	});

	describe("validateAuthorizationCode", () => {
		beforeEach(() => {
			vi.useFakeTimers();
		});

		afterEach(() => {
			vi.useRealTimers();
		});

		it("should return session, token and user on success", async () => {
			const provider = createTestProvider();

			vi.mocked(provider.entraId.validateAuthorizationCode).mockResolvedValue(
				createMockOAuth2Tokens(),
			);
			vi.mocked(decodeIdToken).mockReturnValue({
				aud: "test-aud",
				iss: "test-iss",
				iat: 1234567890,
				nbf: 1234567890,
				exp: 9999999999,
				nonce: "mock-nonce",
				rh: "mock-rh",
				sub: "mock-sub",
				tid: "tenant-id",
				uti: "mock-uti",
				ver: "2.0",
			});

			const result = await provider.validateAuthorizationCode({
				code: "auth-code",
				codeVerifier: "code-verifier",
			});

			expect(result.error).toBeNull();
			expect(result.data).toHaveProperty("token");
			expect(result.data).toHaveProperty("sessionId");
			expect(result.data).toHaveProperty("oauth2Tokens");
		});

		it("should return error result when validation fails", async () => {
			const provider = createTestProvider();

			vi.mocked(
				provider.entraId.validateAuthorizationCode,
			).mockRejectedValueOnce(new Error("Invalid code"));

			const result = await provider.validateAuthorizationCode({
				code: "invalid-code",
				codeVerifier: "verifier",
			});

			expect(result.error).toBeDefined();
		});
	});

	describe("refreshAccessToken", () => {
		beforeEach(() => {
			vi.useFakeTimers();
		});

		afterEach(() => {
			vi.useRealTimers();
		});

		it("should return session, user and token on success", async () => {
			const provider = createTestProvider();

			vi.mocked(provider.entraId.refreshAccessToken).mockResolvedValue(
				createMockOAuth2Tokens(),
			);
			vi.mocked(decodeIdToken).mockReturnValue({
				aud: "test-aud",
				iss: "test-iss",
				iat: 1234567890,
				nbf: 1234567890,
				exp: 9999999999,
				nonce: "mock-nonce",
				rh: "mock-rh",
				sub: "mock-sub",
				tid: "tenant-id",
				uti: "mock-uti",
				ver: "2.0",
			});

			const result = await provider.refreshAccessToken({
				refreshToken: "refresh-token",
				scopes: ["openid", "profile", "email"],
			});

			expect(result.error).toBeNull();
			expect(result.data).toHaveProperty("sessionId");
			expect(result.data).toHaveProperty("token");
			expect(result.data).toHaveProperty("oauth2Tokens");
		});

		it("should return error result when refresh fails", async () => {
			const provider = createTestProvider();

			vi.mocked(provider.entraId.refreshAccessToken).mockRejectedValueOnce(
				new Error("Invalid refresh token"),
			);

			const result = await provider.refreshAccessToken({
				refreshToken: "invalid-refresh-token",
				scopes: ["openid", "profile", "email"],
			});

			expect(result.error).toBeDefined();
		});
	});

	describe("acquireTokenOnBehalfOf", () => {
		beforeEach(() => {
			vi.useFakeTimers();
		});

		afterEach(() => {
			vi.useRealTimers();
		});

		it("should return session and token on success", async () => {
			const provider = createTestProvider();
			const mockResponse = {
				access_token: "obo-access-token",
				token_type: "Bearer",
				expires_in: 3600,
				scope: "https://graph.microsoft.com/.default",
				ext_expires_in: 3600,
			};

			global.fetch = vi.fn().mockResolvedValue({
				ok: true,
				json: () => Promise.resolve(mockResponse),
			}) as unknown as typeof fetch;

			const result = await provider.acquireTokenOnBehalfOf({
				accessToken: "user-access-token",
				scopes: ["https://graph.microsoft.com/.default"],
			});

			expect(result.error).toBeNull();
			expect(result.data).toHaveProperty("sessionId");
			expect(result.data).toHaveProperty("oauth2Tokens");
			expect(result.data).toHaveProperty("token");
		});

		it("should return error on HTTP error", async () => {
			const provider = createTestProvider();

			global.fetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 400,
				statusText: "Bad Request",
			}) as unknown as typeof fetch;

			const result = await provider.acquireTokenOnBehalfOf({
				accessToken: "user-access-token",
				scopes: ["https://graph.microsoft.com/.default"],
			});

			expect(result.error).toBeInstanceOf(AcquireTokenOnBehalfOfError);
		});
	});

	describe("acquireTokenByClientCredential", () => {
		beforeEach(() => {
			vi.useFakeTimers();
		});

		afterEach(() => {
			vi.useRealTimers();
		});

		it("should return token on success", async () => {
			const provider = createTestProvider();
			const mockResponse = {
				access_token: "client-cred-token",
				token_type: "Bearer",
				expires_in: 3600,
			};

			global.fetch = vi.fn().mockResolvedValue({
				ok: true,
				json: () => Promise.resolve(mockResponse),
			}) as unknown as typeof fetch;

			const result = await provider.acquireTokenByClientCredential([
				"https://graph.microsoft.com/.default",
			]);

			expect(result.error).toBeNull();
			expect(result.data).toHaveProperty("oauth2Tokens");
			expect(result.data).toHaveProperty("token");
		});

		it("should return error on HTTP error", async () => {
			const provider = createTestProvider();

			global.fetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 401,
				statusText: "Unauthorized",
			}) as unknown as typeof fetch;

			const result = await provider.acquireTokenByClientCredential([
				"https://graph.microsoft.com/.default",
			]);

			expect(result.error).toBeInstanceOf(AcquireTokenByClientCredentialError);
		});
	});

	describe("Custom Errors", () => {
		it("AcquireTokenOnBehalfOfError should have correct properties", () => {
			const error = new AcquireTokenOnBehalfOfError({
				message: "Test error",
				body: "request-body",
				status: 400,
				statusText: "Bad Request",
				props: { applicationId: "app-1" },
			});

			expect(error.name).toBe("AcquireTokenOnBehalfOfError");
			expect(error.message).toBe("Test error");
			expect(error.body).toBe("request-body");
			expect(error.status).toBe(400);
			expect(error.statusText).toBe("Bad Request");
			expect(error.props).toEqual({ applicationId: "app-1" });
		});

		it("AcquireTokenByClientCredentialError should have correct properties", () => {
			const error = new AcquireTokenByClientCredentialError({
				message: "Test error",
				body: "request-body",
				status: 401,
				statusText: "Unauthorized",
				props: { applicationId: "app-1" },
			});

			expect(error.name).toBe("AcquireTokenByClientCredentialError");
			expect(error.message).toBe("Test error");
			expect(error.body).toBe("request-body");
			expect(error.status).toBe(401);
			expect(error.statusText).toBe("Unauthorized");
			expect(error.props).toEqual({ applicationId: "app-1" });
		});
	});
});
