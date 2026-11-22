// Path patterns:
//   /users/:id          named param (one segment)
//   /files/:name{.+}    param with a custom regex (no capture groups inside)
//   /posts/:slug?       optional trailing param
//   /assets/*           wildcard; a trailing `/*` also matches `/assets` itself
//   *                   everything

export interface CompiledPath {
  regex: RegExp;
  keys: string[];
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function compilePath(pattern: string): CompiledPath {
  if (pattern === "*" || pattern === "/*") return { regex: /^\/.*$|^$/, keys: [] };
  const segments = pattern.split("/").slice(1);
  const keys: string[] = [];
  let source = "";
  segments.forEach((segment, i) => {
    const last = i === segments.length - 1;
    if (segment === "*") {
      source += last ? "(?:/.*)?" : "/[^/]*";
      return;
    }
    const param = /^:([A-Za-z0-9_$]+)(?:\{(.+)\})?(\?)?$/.exec(segment);
    if (param) {
      keys.push(param[1]!);
      const re = param[2] ?? "[^/]+";
      source += param[3] ? `(?:/(${re}))?` : `/(${re})`;
      return;
    }
    source += `/${escape(segment)}`;
  });
  return { regex: new RegExp(`^${source || "/"}$`), keys };
}

export function matchPath(compiled: CompiledPath, path: string): Record<string, string> | null {
  const m = compiled.regex.exec(path);
  if (!m) return null;
  const params: Record<string, string> = {};
  compiled.keys.forEach((key, i) => {
    const raw = m[i + 1];
    if (raw === undefined) return;
    try {
      params[key] = decodeURIComponent(raw);
    } catch {
      params[key] = raw;
    }
  });
  return params;
}

/** `joinPaths('/users', '/')` -> `/users`; `joinPaths('', '/')` -> `/`. */
export function joinPaths(...parts: string[]): string {
  const joined = parts
    .map((p) => p.replace(/^\/+|\/+$/g, ""))
    .filter(Boolean)
    .join("/");
  const trailingSlash = parts.length > 0 && parts[parts.length - 1]!.length > 1 && parts[parts.length - 1]!.endsWith("/");
  return `/${joined}${trailingSlash && joined ? "/" : ""}`;
}
