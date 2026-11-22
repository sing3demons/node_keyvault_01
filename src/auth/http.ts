// Per-request facts the auth routes need from the HTTP layer: which browser this is (device cookie, IP)
// and which auth UI origin emailed links should open.

import { getConnInfo, getCookie, setCookie, type Context } from "../common/kp/index.js";
import { randomToken } from "../shared/crypto.js";
import type { DeviceContext } from "./devices/devices.js";
import type { MailContext } from "./email/email-codes.js";

/** httpOnly cookie that recognizes a browser across sign-ins (value is random; only its hash is stored). */
const DEVICE_COOKIE = "kv_device";
const DEVICE_COOKIE_MAX_AGE = 400 * 24 * 60 * 60; // browsers cap cookie lifetime at 400 days

export class RequestContext {
  constructor(
    /** Origins the login / account pages run on (WEBAUTHN_ORIGINS); emailed links open one of these. */
    private readonly uiOrigins: string[],
    /** Read the client IP from X-Forwarded-For (TRUST_PROXY). */
    private readonly trustProxy = false
  ) {}

  /** The browser behind a sign-in request; gives it a device cookie the first time. */
  device(c: Context): DeviceContext {
    let key = getCookie(c, DEVICE_COOKIE);
    if (!key || !/^[A-Za-z0-9_-]{43}$/.test(key)) {
      key = randomToken();
      setCookie(c, DEVICE_COOKIE, key, {
        httpOnly: true,
        sameSite: "Lax",
        secure: isHttps(c),
        path: "/auth",
        maxAge: DEVICE_COOKIE_MAX_AGE
      });
    }
    return { key, userAgent: c.req.header("user-agent") ?? "", ip: this.clientIp(c) };
  }

  /** Emailed links open the auth UI the request came from (only allow-listed origins). */
  mail(c: Context): MailContext {
    const origin = c.req.header("origin");
    return { uiOrigin: origin && this.uiOrigins.includes(origin) ? origin : this.uiOrigins[0]! };
  }

  private clientIp(c: Context): string | undefined {
    if (this.trustProxy) {
      const forwarded = c.req.header("x-forwarded-for")?.split(",")[0]?.trim();
      if (forwarded) return forwarded.slice(0, 64);
    }
    return getConnInfo(c).remote.address; // undefined when not running on the Node server (e.g. tests)
  }
}

export const isHttps = (c: Context) => new URL(c.req.url).protocol === "https:";

/** `Authorization: Bearer <token>` -> the token. */
export const bearerToken = (c: Context): string | undefined => /^Bearer\s+(\S+)$/i.exec(c.req.header("Authorization") ?? "")?.[1];
