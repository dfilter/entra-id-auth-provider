import z from "zod";

export const defaultTokenSchema = z.object({
  token_type: z.enum(["Bearer"]),
  expires_in: z.number(),
  access_token: z.string(),
});

export const oboTokenSchema = defaultTokenSchema.extend({
  scope: z.string(),
  ext_expires_in: z.number(),
  refresh_token: z.string().optional(),
  id_token: z.string().optional(),
});

export const idTokenSchema = z.object({
  aud: z.string(),
  iss: z.string(),
  iat: z.number(),
  nbf: z.number(),
  exp: z.number(),
  acct: z.number(),
  email: z.string(),
  name: z.string(),
  nonce: z.string().optional(),
  oid: z.string(),
  preferred_username: z.string(),
  rh: z.string(),
  roles: z.string().array().nullish(),
  sid: z.string(),
  sub: z.string(),
  tid: z.string(),
  uti: z.string(),
  ver: z.string(),
});
