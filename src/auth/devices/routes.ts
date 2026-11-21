// /auth/me/devices: browsers the signed-in user has signed in from.

import type { Hono, MiddlewareHandler } from "hono";
import { parse } from "../../shared/http.js";
import type { AuthEnv } from "../../shared/middleware.js";
import { credentialIdParam } from "../schemas.js";
import type { DeviceService } from "./devices.js";

export function registerDeviceRoutes(
  app: Hono<AuthEnv>,
  { devices, bearer }: { devices: DeviceService; bearer: MiddlewareHandler<AuthEnv> }
) {
  app.get("/auth/me/devices", bearer, async (c) => {
    const user = c.get("user");
    return c.json({ devices: await devices.list(user.id, user.deviceId) });
  });

  /** Revoke the device's sessions, keep it in the history. */
  app.post("/auth/me/devices/:id/sign-out", bearer, async (c) => {
    const { id } = parse(credentialIdParam, c.req.param());
    const user = c.get("user");
    await devices.signOut(user.id, id, user.deviceId);
    return c.body(null, 204);
  });

  /** Sign the device out and forget it. */
  app.delete("/auth/me/devices/:id", bearer, async (c) => {
    const { id } = parse(credentialIdParam, c.req.param());
    const user = c.get("user");
    await devices.remove(user.id, id, user.deviceId);
    return c.body(null, 204);
  });
}
