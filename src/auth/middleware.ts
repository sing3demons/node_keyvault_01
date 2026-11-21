import type { MiddlewareHandler } from "hono";
import type { AuthenticatedUser, AuthService } from "./service.js";

export type AuthEnv = { Variables: { user: AuthenticatedUser } };

/** Requires `Authorization: Bearer <opaque access token>` (RFC 6750). */
export function requireAuth(service: AuthService, scope?: string): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const header = c.req.header("Authorization") ?? "";
    const match = /^Bearer\s+([A-Za-z0-9_-]+)$/i.exec(header);
    const user = match ? await service.authenticate(match[1]) : null;
    if (!user) {
      c.header("WWW-Authenticate", match ? 'Bearer error="invalid_token"' : "Bearer");
      return c.json({ message: "Unauthorized" }, 401);
    }
    if (scope && !user.scope.split(" ").includes(scope)) {
      c.header("WWW-Authenticate", `Bearer error="insufficient_scope", scope="${scope}"`);
      return c.json({ message: "Insufficient scope" }, 403);
    }
    c.set("user", user);
    await next();
  };
}
