// Devices a user signed in from: recorded on every sign-in, listed in the account, and removable
// (which signs that device out by revoking the tokens it was issued).

import { randomUUID } from "node:crypto";
import { sha256 } from "../../shared/crypto.js";
import { HttpError } from "../../shared/http.js";
import type { SignInMethod } from "../model.js";
import type { AuthRepository } from "../repository.js";

/** What the HTTP layer knows about the browser making a sign-in request. */
export interface DeviceContext {
  /** Raw value of the device cookie (random, 256 bits). */
  key: string;
  userAgent: string;
  ip?: string;
}

export interface DeviceView {
  id: string;
  name: string;
  userAgent: string;
  ip?: string;
  firstSignInAt: string;
  lastSignInAt: string;
  lastSeenAt: string;
  lastMethod: SignInMethod;
  signIns: number;
  /** Holds a usable session right now (not signed out / expired). */
  active: boolean;
  /** The device making this request. */
  current: boolean;
}

export class DeviceService {
  constructor(private readonly repo: AuthRepository) {}

  /** @returns the device id to bind the issued tokens to */
  recordSignIn(userId: string, ctx: DeviceContext, method: SignInMethod): Promise<string> {
    const userAgent = ctx.userAgent.slice(0, 512);
    return this.repo.devices.recordSignIn({
      id: randomUUID(),
      userId,
      keyHash: sha256(ctx.key),
      name: describeUserAgent(userAgent),
      userAgent,
      ...(ctx.ip ? { ip: ctx.ip } : {}),
      at: new Date(),
      method
    });
  }

  /** Token refresh = the device is still in use. */
  touch(deviceId: string): Promise<void> {
    return this.repo.devices.touch(deviceId, new Date());
  }

  async list(userId: string, currentDeviceId?: string): Promise<DeviceView[]> {
    const now = new Date();
    const [devices, active] = await Promise.all([
      this.repo.devices.listByUser(userId),
      this.repo.tokens.activeDeviceIds(userId, now)
    ]);
    const activeIds = new Set(active);
    return devices.map((d) => ({
      id: d.id,
      name: d.name,
      userAgent: d.userAgent,
      ...(d.ip !== undefined ? { ip: d.ip } : {}),
      firstSignInAt: d.createdAt.toISOString(),
      lastSignInAt: d.lastSignInAt.toISOString(),
      lastSeenAt: d.lastSeenAt.toISOString(),
      lastMethod: d.lastMethod,
      signIns: d.signIns,
      active: activeIds.has(d.id),
      current: d.id === currentDeviceId
    }));
  }

  /** Signs the device out (revokes its tokens) and forgets it. */
  async remove(userId: string, deviceId: string, currentDeviceId?: string): Promise<void> {
    if (deviceId === currentDeviceId) {
      throw new HttpError(409, "This is the device you are using — use Log out instead", "conflict");
    }
    // revoke first: a device that is gone from the list must not keep a working session
    await this.repo.tokens.revokeDevice(userId, deviceId);
    if (!(await this.repo.devices.delete(userId, deviceId))) throw new HttpError(404, "Device not found");
  }

  /** Signs the device out but keeps it in the history. */
  async signOut(userId: string, deviceId: string, currentDeviceId?: string): Promise<void> {
    if (deviceId === currentDeviceId) {
      throw new HttpError(409, "This is the device you are using — use Log out instead", "conflict");
    }
    if (!(await this.repo.devices.listByUser(userId)).some((d) => d.id === deviceId)) {
      throw new HttpError(404, "Device not found");
    }
    await this.repo.tokens.revokeDevice(userId, deviceId);
  }
}

/** "Mozilla/5.0 (Macintosh; …) … Chrome/131…" -> "Chrome on macOS". Good enough for a device list. */
export function describeUserAgent(ua: string): string {
  if (!ua) return "Unknown device";
  const browser =
    /\bEdg(?:e|A|iOS)?\//.test(ua) ? "Edge"
    : /\bOPR\/|\bOpera\b/.test(ua) ? "Opera"
    : /\bSamsungBrowser\//.test(ua) ? "Samsung Internet"
    : /\bFirefox\/|\bFxiOS\//.test(ua) ? "Firefox"
    : /\bChrome\/|\bCriOS\//.test(ua) ? "Chrome"
    : /\bSafari\//.test(ua) && /\bVersion\//.test(ua) ? "Safari"
    : /\bcurl\//i.test(ua) ? "curl"
    : undefined;
  const os =
    /\biPhone\b/.test(ua) ? "iPhone"
    : /\biPad\b/.test(ua) ? "iPad"
    : /\bAndroid\b/.test(ua) ? "Android"
    : /\bWindows\b/.test(ua) ? "Windows"
    : /\bCrOS\b/.test(ua) ? "ChromeOS"
    : /\bMac OS X\b|\bMacintosh\b/.test(ua) ? "macOS"
    : /\bLinux\b/.test(ua) ? "Linux"
    : undefined;
  if (browser && os) return `${browser} on ${os}`;
  return browser ?? os ?? ua.slice(0, 40);
}
