// /auth/me (the signed-in user's account) and /admin/users (admins: roles).

import { Controller, Get, Patch, Put, UseInterceptors, type Ctx } from "../../common/kp/index.js";
import { Bearer, requireRole } from "../../shared/middleware.js";
import { setRolesBody, updateAccountBody, usernameParam } from "../schemas.js";
import type { AccountService } from "./service.js";

@Controller("/auth/me")
@UseInterceptors(Bearer)
export class AccountController {
  constructor(private readonly accounts: AccountService) {}

  @Get("/")
  async me(c: Ctx) {
    return c.json(await this.accounts.get(c.get("user").id));
  }

  /** email, profiles, preferredLang */
  @Patch("/")
  async update(c: Ctx) {
    const body = await c.safeBody(updateAccountBody);
    return c.json(await this.accounts.update(c.get("user").id, body));
  }
}

/** Administration (role "admin"). */
@Controller("/admin/users")
@UseInterceptors(Bearer, requireRole("admin"))
export class UserAdminController {
  constructor(private readonly accounts: AccountService) {}

  @Get("/")
  async list(c: Ctx) {
    return c.json({ users: await this.accounts.list() });
  }

  /** body: { roles } */
  @Put("/:username/roles")
  async setRoles(c: Ctx) {
    const { username } = c.safeParam(usernameParam);
    const { roles } = await c.safeBody(setRolesBody);
    return c.json(await this.accounts.setRoles(username, roles));
  }
}
