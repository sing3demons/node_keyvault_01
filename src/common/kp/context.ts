import { ValidationError, type ValidationTarget } from "./errors.js";
import { KpRequest } from "./request.js";
import type { InferOutput, Issue, StandardSchemaV1 } from "./standard-schema.js";
import type { Bindings, Env, Input, NotFoundHandler, Variables } from "./types.js";

type HeaderRecord = Record<string, string | string[]>;
type Body = ConstructorParameters<typeof Response>[0];

export type ValidateResult<T> = { ok: true; value: T } | { ok: false; error: ReadonlyArray<Issue> };

const JSON_TYPE = "application/json";
const TEXT_TYPE = "text/plain; charset=UTF-8";
const HTML_TYPE = "text/html; charset=UTF-8";

/** Per-request context: the request (`c.req`), response builders, variables and validation helpers. */
export class Context<E extends Env = Env, P extends string = string, I extends Input = {}> {
  readonly req: KpRequest<P, I>;
  /** What the server adapter passed (Node: `{ incoming, outgoing }`). */
  readonly env: Bindings<E>;
  /** The error a handler threw, once the error handler ran. */
  error: Error | undefined;

  #status = 200;
  #headers: Headers | undefined;
  #res: Response | undefined;
  #vars = new Map<PropertyKey, unknown>();
  #notFound: NotFoundHandler<any>;
  #event: string | undefined;

  constructor(request: Request, env: unknown, notFound: NotFoundHandler<any>) {
    this.req = new KpRequest<P, I>(request);
    this.env = (env ?? {}) as Bindings<E>;
    this.#notFound = notFound;
  }

  /** The `cmd` of the matched route: `@Get("/authorize", "authorize")` -> `"authorize"` (undefined when none). */
  Event(): string | undefined {
    return this.#event;
  }

  /** @internal set by the app once the route is matched */
  setEvent(event: string | undefined): void {
    this.#event = event;
  }

  // -------------------------------------------------------------- variables

  get<K extends keyof Variables<E>>(key: K): Variables<E>[K] {
    return this.#vars.get(key) as Variables<E>[K];
  }

  set<K extends keyof Variables<E>>(key: K, value: Variables<E>[K]): void {
    this.#vars.set(key, value);
  }

  // -------------------------------------------------------------- response

  /** True once a handler produced the response. */
  get finalized(): boolean {
    return this.#res !== undefined;
  }

  /** The response so far; middleware can read or replace it after `await next()`. */
  get res(): Response {
    return (this.#res ??= new Response(null, { status: 404 }));
  }

  set res(response: Response) {
    this.#res = response;
  }

  status(code: number): this {
    this.#status = code;
    return this;
  }

  /** Before a response exists the header is kept for it; afterwards (after `await next()`) it changes `c.res`. */
  header(name: string, value: string | undefined, options: { append?: boolean } = {}): void {
    if (this.#res) {
      const apply = (h: Headers) =>
        value === undefined ? h.delete(name) : options.append ? h.append(name, value) : h.set(name, value);
      try {
        apply(this.#res.headers);
      } catch {
        // immutable headers (e.g. Response.redirect / fetch): copy the response first
        this.#res = new Response(this.#res.body, this.#res);
        apply(this.#res.headers);
      }
      return;
    }
    const headers = (this.#headers ??= new Headers());
    if (value === undefined) headers.delete(name);
    else if (options.append) headers.append(name, value);
    else headers.set(name, value);
  }

  /** A response with no content-type set for you (string, bytes, stream or null). */
  body(data: Body | null, status?: number, headers?: HeaderRecord): Response {
    return this.#respond(data, status, headers);
  }

  json<T>(data: T, status?: number, headers?: HeaderRecord): Response {
    return this.#respond(JSON.stringify(data), status, headers, JSON_TYPE);
  }

  text(text: string, status?: number, headers?: HeaderRecord): Response {
    return this.#respond(text, status, headers, TEXT_TYPE);
  }

  html(html: string, status?: number, headers?: HeaderRecord): Response {
    return this.#respond(html, status, headers, HTML_TYPE);
  }

  redirect(location: string, status: 301 | 302 | 303 | 307 | 308 = 302): Response {
    return this.#respond(null, status, { Location: location });
  }

  notFound(): Response | Promise<Response> {
    return this.#notFound(this as Context<any, any, any>);
  }

  #respond(data: Body | null, status: number | undefined, extra: HeaderRecord | undefined, contentType?: string): Response {
    const headers = new Headers(this.#headers);
    if (contentType && !headers.has("content-type")) headers.set("content-type", contentType);
    for (const [name, value] of Object.entries(extra ?? {})) {
      if (Array.isArray(value)) {
        headers.delete(name);
        for (const v of value) headers.append(name, v);
      } else headers.set(name, value);
    }
    return new Response(data, { status: status ?? this.#status, headers });
  }

  // -------------------------------------------------------------- validation (throws ValidationError -> 400)

  safeQuery<S extends StandardSchemaV1>(schema: S): InferOutput<S> {
    return this.#check("query", schema, this.req.query());
  }

  safeParam<S extends StandardSchemaV1>(schema: S): InferOutput<S> {
    return this.#check("param", schema, this.req.param());
  }

  /** Header names in the schema must be lower-case. */
  safeHeader<S extends StandardSchemaV1>(schema: S): InferOutput<S> {
    return this.#check("header", schema, this.req.header());
  }

  /** JSON body; a body that is not JSON fails the same way. */
  async safeBody<S extends StandardSchemaV1>(schema: S): Promise<InferOutput<S>> {
    const data = await readJson(this.req);
    return checkResult("json", await schema["~standard"].validate(data));
  }

  async safeForm<S extends StandardSchemaV1>(schema: S): Promise<InferOutput<S>> {
    const data = await this.req.parseBody();
    return checkResult("form", await schema["~standard"].validate(data));
  }

  /** Check anything without throwing (sync schemas). */
  validate<S extends StandardSchemaV1>(schema: S, data: unknown): ValidateResult<InferOutput<S>> {
    return toResult(syncResult(schema, data));
  }

  async validateAsync<S extends StandardSchemaV1>(schema: S, data: unknown): Promise<ValidateResult<InferOutput<S>>> {
    return toResult(await schema["~standard"].validate(data));
  }

  #check<S extends StandardSchemaV1>(target: ValidationTarget, schema: S, data: unknown): InferOutput<S> {
    return checkResult(target, syncResult(schema, data));
  }
}

/** `Ctx<'/:id'>` types `c.req.param('id')`; plain `Ctx` accepts any key. */
export type Ctx<P extends string = string, E extends Env = Env, I extends Input = {}> = Context<E, P, I>;

export async function readJson(req: KpRequest<any, any>): Promise<unknown> {
  try {
    return await req.json();
  } catch {
    throw new ValidationError("json", [{ message: "Request body must be valid JSON" }]);
  }
}

function syncResult(schema: StandardSchemaV1, data: unknown): StandardSchemaV1.Result<unknown> {
  const result = schema["~standard"].validate(data);
  if (result instanceof Promise) throw new TypeError("Schema validates asynchronously; use the async variant");
  return result;
}

function checkResult<T>(target: ValidationTarget, result: StandardSchemaV1.Result<unknown>): T {
  if (result.issues) throw new ValidationError(target, result.issues);
  return result.value as T;
}

function toResult<T>(result: StandardSchemaV1.Result<unknown>): ValidateResult<T> {
  return result.issues ? { ok: false, error: result.issues } : { ok: true, value: result.value as T };
}
