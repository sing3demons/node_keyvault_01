// /auth/me/devices: browsers the signed-in user has signed in from.

import { Controller, Delete, Get, Post, UseInterceptors, type Ctx } from "../../common/kp/index.js";
import { Bearer } from "../../shared/middleware.js";
import { credentialIdParam } from "../schemas.js";
import type { DeviceService } from "./devices.js";

@Controller("/auth/me/devices")
@UseInterceptors(Bearer)
export class DeviceController {
  constructor(private readonly devices: DeviceService) {}

  @Get("/")
  async list(c: Ctx) {
    const user = c.get("user");
    return c.json({ devices: await this.devices.list(user.id, user.deviceId) });
  }

  /** Revoke the device's sessions, keep it in the history. */
  @Post("/:id/sign-out")
  async signOut(c: Ctx) {
    const { id } = c.safeParam(credentialIdParam);
    const user = c.get("user");
    await this.devices.signOut(user.id, id, user.deviceId);
    return c.body(null, 204);
  }

  /** Sign the device out and forget it. */
  @Delete("/:id")
  async remove(c: Ctx) {
    const { id } = c.safeParam(credentialIdParam);
    const user = c.get("user");
    await this.devices.remove(user.id, id, user.deviceId);
    return c.body(null, 204);
  }
}
