// /auth/webauthn/*: passkey management for the signed-in user (signing in with one: sign-in/controller.ts).

import { Controller, Delete, Get, Patch, Post, UseInterceptors, type Ctx } from "../../common/kp/index.js";
import { Bearer } from "../../shared/middleware.js";
import { credentialIdParam, passkeyRegisterVerifyBody, passkeyRenameBody } from "../schemas.js";
import type { WebAuthnService } from "./webauthn.js";

@Controller("/auth/webauthn")
@UseInterceptors(Bearer)
export class PasskeyController {
  constructor(private readonly webauthn: WebAuthnService) {}

  @Post("/register/options")
  async registrationOptions(c: Ctx) {
    const user = c.get("user");
    return c.json(await this.webauthn.registrationOptions(user.id, user.username));
  }

  @Post("/register/verify")
  async verifyRegistration(c: Ctx) {
    const user = c.get("user");
    const body = await c.safeBody(passkeyRegisterVerifyBody);
    return c.json(await this.webauthn.verifyRegistration(user.id, body.challengeId, body.credential, body.name), 201);
  }

  @Get("/credentials")
  async list(c: Ctx) {
    return c.json({ passkeys: await this.webauthn.list(c.get("user").id) });
  }

  @Patch("/credentials/:id")
  async rename(c: Ctx) {
    const { id } = c.safeParam(credentialIdParam);
    const { name } = await c.safeBody(passkeyRenameBody);
    return c.json(await this.webauthn.rename(c.get("user").id, id, name));
  }

  @Delete("/credentials/:id")
  async remove(c: Ctx) {
    const { id } = c.safeParam(credentialIdParam);
    await this.webauthn.remove(c.get("user").id, id);
    return c.body(null, 204);
  }
}
