// Route middleware shared by every module. Depends only on the TokenAuthenticator contract,
// so any module can protect its routes without importing the auth implementation.

import type { MiddlewareHandler } from "hono";
import { HttpError } from "./http.js";

/** The caller behind a valid access token. */
export interface AuthenticatedUser {
  id: string;
  username: string;
  scope: string;
  clientId: string;
  /** Current roles, read from the user record on every request (so revoking takes effect at once). */
  roles: string[];
  /** Device the token was issued to (absent for tokens from before devices were tracked). */
  deviceId?: string;
  /** The sign-in session (access + refresh tokens) the token belongs to. */
  familyId?: string;
}

/** Resolves an access token to its user, or null when it is unknown or expired. */
export interface TokenAuthenticator {
  authenticate(accessToken: string): Promise<AuthenticatedUser | null>;
}

/** Hono env for routes behind requireAuth: `c.get("user")` is the authenticated caller. */
export type AuthEnv = {
  Variables: {
    user: AuthenticatedUser;
    /** Set (instead of `user`) when the request authenticated as the master credential. */
    master?: { username: string };
  };
};

/** Requires `Authorization: Bearer <access token>` (RFC 6750), optionally with a scope. */
export function requireAuth(authenticator: TokenAuthenticator, scope?: string): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const header = c.req.header("Authorization") ?? "";
    const match = /^Bearer\s+([A-Za-z0-9_-]+)$/i.exec(header);
    const user = match ? await authenticator.authenticate(match[1]) : null;
    if (!user) {
      // RFC 6750 §3.1: no error code in the challenge when no token was sent at all
      c.header("WWW-Authenticate", match ? 'Bearer error="invalid_token"' : "Bearer");
      throw new HttpError(401, match ? "Access token is invalid or expired" : "Bearer token required", "invalid_token");
    }
    if (scope && !user.scope.split(" ").includes(scope)) {
      c.header("WWW-Authenticate", `Bearer error="insufficient_scope", scope="${scope}"`);
      throw new HttpError(403, `Token lacks the "${scope}" scope`, "insufficient_scope");
    }
    c.set("user", user);
    await next();
  };
}

/** Use after requireAuth: only callers holding `role` get through (403 otherwise). */
export function requireRole(role: string): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    if (!c.get("user").roles.includes(role)) {
      throw new HttpError(403, `Requires the "${role}" role`, "access_denied");
    }
    await next();
  };
}

/**
 * Admin routes the master credential may also use: a master session token (from the master sign-in, which
 * includes email verification), else a Bearer token of a user holding `role`.
 */
export function requireRoleOrMaster(
  authenticator: TokenAuthenticator,
  role: string,
  masterSession: (accessToken: string) => Promise<{ username: string } | null>
): MiddlewareHandler<AuthEnv> {
  const bearer = requireAuth(authenticator);
  const hasRole = requireRole(role);
  return async (c, next) => {
    const match = /^Bearer\s+([A-Za-z0-9_-]+)$/i.exec(c.req.header("Authorization") ?? "");
    const master = match ? await masterSession(match[1]!) : null;
    if (master) {
      c.set("master", master);
      return next();
    }
    return bearer(c, async () => {
      await hasRole(c, next);
    });
  };
}
