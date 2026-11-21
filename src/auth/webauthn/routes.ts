// /auth/webauthn/*: passkey management for the signed-in user (signing in with one: sign-in/routes.ts).

import type { Hono, MiddlewareHandler } from "hono";
import { parse, parseJsonBody } from "../../shared/http.js";
import type { AuthEnv } from "../../shared/middleware.js";
import { credentialIdParam, passkeyRegisterVerifyBody } from "../schemas.js";
import type { WebAuthnService } from "./webauthn.js";

export function registerPasskeyRoutes(
  app: Hono<AuthEnv>,
  { webauthn, bearer }: { webauthn: WebAuthnService; bearer: MiddlewareHandler<AuthEnv> }
) {
  app.post("/auth/webauthn/register/options", bearer, async (c) => {
    const user = c.get("user");
    return c.json(await webauthn.registrationOptions(user.id, user.username));
  });

  app.post("/auth/webauthn/register/verify", bearer, async (c) => {
    const user = c.get("user");
    const body = await parseJsonBody(c, passkeyRegisterVerifyBody);
    return c.json(await webauthn.verifyRegistration(user.id, body.challengeId, body.credential, body.name), 201);
  });

  app.get("/auth/webauthn/credentials", bearer, async (c) => c.json({ passkeys: await webauthn.list(c.get("user").id) }));

  app.delete("/auth/webauthn/credentials/:id", bearer, async (c) => {
    const { id } = parse(credentialIdParam, c.req.param());
    await webauthn.remove(c.get("user").id, id);
    return c.body(null, 204);
  });
}
