import z from "zod";

export const defaultTokenSchema = z.object({
	token_type: z.string(),
	expires_in: z.number(),
	access_token: z.string(),
});
export type DefaultTokenResponse = z.infer<typeof defaultTokenSchema>;

export const oboTokenSchema = defaultTokenSchema.extend({
	scope: z.string(),
	ext_expires_in: z.number(),
	refresh_token: z.string().optional(),
	id_token: z.string().optional(),
});

export const baseIdTokenSchema = z.object({
	aud: z.string(),
	iss: z.string(),
	iat: z.number(),
	nbf: z.number(),
	exp: z.number(),
	nonce: z.string(),
	rh: z.string(),
	sub: z.string(),
	tid: z.string(),
	uti: z.string(),
	ver: z.string(),
});
export type BaseIdToken = z.infer<typeof baseIdTokenSchema>;
