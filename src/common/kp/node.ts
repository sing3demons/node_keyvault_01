// Node.js adapter: run a fetch handler on node:http, serve files, read the client address.

import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { extname, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { TLSSocket } from "node:tls";
import type { Context } from "./context.js";
import type { MiddlewareHandler } from "./types.js";

/** What `serve` passes as `c.env`. */
export interface NodeBindings {
  incoming: IncomingMessage;
  outgoing: ServerResponse;
}

export type FetchHandler = (request: Request, env: NodeBindings) => Response | Promise<Response>;

export interface ServeOptions {
  fetch: FetchHandler;
  port?: number;
  hostname?: string;
}

export function serve(options: ServeOptions, onListen?: (info: AddressInfo) => void): Server {
  const server = createServer((incoming, outgoing) => {
    void handle(options.fetch, incoming, outgoing);
  });
  server.listen(options.port ?? 3000, options.hostname, () => onListen?.(server.address() as AddressInfo));
  return server;
}

async function handle(fetch: FetchHandler, incoming: IncomingMessage, outgoing: ServerResponse): Promise<void> {
  let request: Request;
  try {
    request = toRequest(incoming, outgoing);
  } catch {
    outgoing.writeHead(400).end("Bad Request");
    return;
  }
  try {
    const response = await fetch(request, { incoming, outgoing });
    await writeResponse(response, outgoing, incoming.method === "HEAD");
  } catch (err) {
    console.error(err);
    if (!outgoing.headersSent) outgoing.writeHead(500, { "content-type": "text/plain; charset=UTF-8" });
    outgoing.end(outgoing.headersSent ? undefined : "Internal Server Error");
  }
}

function toRequest(incoming: IncomingMessage, outgoing: ServerResponse): Request {
  const protocol = (incoming.socket as TLSSocket).encrypted ? "https" : "http";
  const url = new URL(incoming.url ?? "/", `${protocol}://${incoming.headers.host ?? "localhost"}`);

  const headers = new Headers();
  const raw = incoming.rawHeaders;
  for (let i = 0; i < raw.length; i += 2) {
    if (!raw[i]!.startsWith(":")) headers.append(raw[i]!, raw[i + 1]!);
  }

  const abort = new AbortController();
  outgoing.on("close", () => {
    if (!outgoing.writableFinished) abort.abort();
  });

  const method = incoming.method ?? "GET";
  const hasBody = method !== "GET" && method !== "HEAD";
  return new Request(url, {
    method,
    headers,
    signal: abort.signal,
    ...(hasBody ? { body: Readable.toWeb(incoming) as ReadableStream, duplex: "half" } : {})
  } as RequestInit);
}

async function writeResponse(response: Response, outgoing: ServerResponse, head: boolean): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((value, name) => {
    if (name !== "set-cookie") headers[name] = value;
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length) headers["set-cookie"] = cookies;
  outgoing.writeHead(response.status, headers);

  if (!response.body || head) {
    outgoing.end();
    return;
  }
  try {
    await pipeline(Readable.fromWeb(response.body as import("node:stream/web").ReadableStream), outgoing);
  } catch {
    outgoing.destroy(); // client went away mid-stream
  }
}

/** Client address of the socket (not X-Forwarded-For). */
export function getConnInfo(c: Context<any, any, any>): { remote: { address?: string; port?: number } } {
  const socket = (c.env as Partial<NodeBindings>).incoming?.socket;
  return { remote: { ...(socket?.remoteAddress ? { address: socket.remoteAddress } : {}), ...(socket?.remotePort ? { port: socket.remotePort } : {}) } };
}

// ---------------------------------------------------------------- static files

const MIME: Record<string, string> = {
  ".html": "text/html; charset=UTF-8",
  ".htm": "text/html; charset=UTF-8",
  ".js": "text/javascript; charset=UTF-8",
  ".mjs": "text/javascript; charset=UTF-8",
  ".css": "text/css; charset=UTF-8",
  ".json": "application/json",
  ".map": "application/json",
  ".webmanifest": "application/manifest+json",
  ".txt": "text/plain; charset=UTF-8",
  ".xml": "application/xml",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".wasm": "application/wasm",
  ".pdf": "application/pdf"
};

export interface ServeStaticOptions {
  /** Directory the URL path maps into. */
  root?: string;
  /** Always serve this one file (SPA fallback). */
  path?: string;
  /** File for directory URLs, default index.html. */
  index?: string;
}

/** GET / HEAD file server; calls `next()` when there is no such file. Never leaves `root`. */
export function serveStatic(options: ServeStaticOptions): MiddlewareHandler<any, any> {
  const root = resolve(options.root ?? ".");
  const index = options.index ?? "index.html";
  return async (c, next) => {
    if (c.finalized || (c.req.method !== "GET" && c.req.method !== "HEAD")) return next();

    let file: string;
    if (options.path) {
      file = resolve(options.path);
    } else {
      let urlPath: string;
      try {
        urlPath = decodeURIComponent(c.req.path);
      } catch {
        return next();
      }
      if (urlPath.includes("\0")) return next();
      file = resolve(root, `.${urlPath}`);
      if (file !== root && !file.startsWith(root + sep)) return next();
      if (urlPath.endsWith("/")) file = resolve(file, index);
    }

    let info = await stat(file).catch(() => undefined);
    if (info?.isDirectory()) {
      file = resolve(file, index);
      info = await stat(file).catch(() => undefined);
    }
    if (!info?.isFile()) return next();

    c.header("Content-Type", MIME[extname(file).toLowerCase()] ?? "application/octet-stream");
    c.header("Content-Length", String(info.size));
    c.header("Last-Modified", info.mtime.toUTCString());
    if (c.req.method === "HEAD") return c.body(null, 200);
    return c.body(Readable.toWeb(createReadStream(file)) as ReadableStream, 200);
  };
}
