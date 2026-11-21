// /auth/me (the signed-in user's account) and /admin/users (admins: roles).

import type { Hono, MiddlewareHandler } from "hono";
import { parse, parseJsonBody } from "../../shared/http.js";
import { requireRole, type AuthEnv } from "../../shared/middleware.js";
import { setRolesBody, updateAccountBody, usernameParam } from "../schemas.js";
import type { AccountService } from "./service.js";

export function registerAccountRoutes(
  app: Hono<AuthEnv>,
  { accounts, bearer }: { accounts: AccountService; bearer: MiddlewareHandler<AuthEnv> }
) {
  app.get("/auth/me", bearer, async (c) => c.json(await accounts.get(c.get("user").id)));

  /** email, profiles, preferredLang */
  app.patch("/auth/me", bearer, async (c) => {
    const body = await parseJsonBody(c, updateAccountBody);
    return c.json(await accounts.update(c.get("user").id, body));
  });

  // --- administration (role "admin")
  app.use("/admin/users", bearer, requireRole("admin"));
  app.use("/admin/users/*", bearer, requireRole("admin"));

  app.get("/admin/users", async (c) => c.json({ users: await accounts.list() }));

  /** body: { roles } */
  app.put("/admin/users/:username/roles", async (c) => {
    const { username } = parse(usernameParam, c.req.param());
    const { roles } = await parseJsonBody(c, setRolesBody);
    return c.json(await accounts.setRoles(username, roles));
  });
}
