import { z } from "zod";
import { PERMISSIONS } from "./acl.js";

/** Azure Key Vault secret names: 1-127 characters, letters, digits and dashes. */
export const secretNameParam = z.object({
  name: z
    .string()
    .regex(/^[0-9a-zA-Z-]{1,127}$/, "Secret name must be 1-127 characters: letters, digits and dashes")
});

/** Azure Key Vault limits a secret value to 25 KB. */
const MAX_VALUE_BYTES = 25 * 1024;

export const setSecretBody = z.object({
  value: z
    .string()
    .min(1, "value must not be empty")
    .refine((v) => Buffer.byteLength(v, "utf8") <= MAX_VALUE_BYTES, "value must be at most 25 KB")
});

export type SecretName = z.infer<typeof secretNameParam>["name"];
export type SetSecretBody = z.infer<typeof setSecretBody>;

/** PUT /secrets/:name/grants/:username */
export const grantParams = secretNameParam.extend({
  username: z.string().trim().min(1).max(64)
});

export const setGrantBody = z.object({
  /** Empty list = revoke. Seeing the name needs no grant. */
  permissions: z.array(z.enum(PERMISSIONS)).max(PERMISSIONS.length)
});

/** PUT /secrets/:name/owner */
export const transferBody = z.object({ username: z.string().trim().min(1).max(64) });
