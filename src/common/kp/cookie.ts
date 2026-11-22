import type { Context } from "./context.js";

export interface CookieOptions {
  domain?: string;
  expires?: Date;
  httpOnly?: boolean;
  /** seconds */
  maxAge?: number;
  /** default "/" */
  path?: string;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  partitioned?: boolean;
}

const decode = (v: string) => {
  try {
    return decodeURIComponent(v);
  } catch {
    return v;
  }
};

function parseCookies(header: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const name = pair.slice(0, eq).trim();
    if (!name || name in out) continue;
    let value = pair.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    out[name] = decode(value);
  }
  return out;
}

export function getCookie(c: Context<any, any, any>): Record<string, string>;
export function getCookie(c: Context<any, any, any>, name: string): string | undefined;
export function getCookie(c: Context<any, any, any>, name?: string): unknown {
  const cookies = parseCookies(c.req.header("cookie") ?? "");
  return name === undefined ? cookies : cookies[name];
}

export function serializeCookie(name: string, value: string, opt: CookieOptions = {}): string {
  if (!/^[\w!#$%&'*.^`|~+-]+$/.test(name)) throw new TypeError(`Invalid cookie name: ${name}`);
  let cookie = `${name}=${encodeURIComponent(value)}`;
  if (opt.maxAge !== undefined) cookie += `; Max-Age=${Math.floor(opt.maxAge)}`;
  if (opt.domain) cookie += `; Domain=${opt.domain}`;
  cookie += `; Path=${opt.path ?? "/"}`;
  if (opt.expires) cookie += `; Expires=${opt.expires.toUTCString()}`;
  if (opt.httpOnly) cookie += "; HttpOnly";
  if (opt.secure) cookie += "; Secure";
  if (opt.sameSite) cookie += `; SameSite=${opt.sameSite}`;
  if (opt.partitioned) cookie += "; Partitioned";
  return cookie;
}

export function setCookie(c: Context<any, any, any>, name: string, value: string, options?: CookieOptions): void {
  c.header("Set-Cookie", serializeCookie(name, value, options), { append: true });
}

/** Expires the cookie (use the same path / domain it was set with); returns its old value. */
export function deleteCookie(c: Context<any, any, any>, name: string, options: Omit<CookieOptions, "maxAge" | "expires"> = {}): string | undefined {
  const old = getCookie(c, name);
  setCookie(c, name, "", { ...options, maxAge: 0, expires: new Date(0) });
  return old;
}
