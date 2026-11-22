import { Context } from "./context.js";
import {
  controllerRoutes,
  isControllerInstance,
  isInterceptorClass,
  type Interceptor,
  type InterceptorClass,
  type InterceptorLike
} from "./decorators.js";
import { HTTPException, ValidationError } from "./errors.js";
import { compilePath, joinPaths, matchPath, type CompiledPath } from "./router.js";
import type { Env, ErrorHandler, Handler, Input, MiddlewareHandler, NotFoundHandler } from "./types.js";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const;
const ALL = "ALL";

interface Route {
  method: string;
  path: string;
  compiled: CompiledPath;
  handler: Handler<any, any, any>;
}

/** Route registration, with validator() output typed through to the handler (up to 3 middleware). */
interface RouteMethod<E extends Env, Self> {
  <P extends string>(path: P, handler: Handler<E, NoInfer<P>, {}>): Self;
  <P extends string, I1 extends Input>(path: P, m1: Handler<E, NoInfer<P>, I1>, handler: Handler<E, NoInfer<P>, I1>): Self;
  <P extends string, I1 extends Input, I2 extends Input>(
    path: P,
    m1: Handler<E, NoInfer<P>, I1>,
    m2: Handler<E, NoInfer<P>, I2>,
    handler: Handler<E, NoInfer<P>, I1 & I2>
  ): Self;
  <P extends string, I1 extends Input, I2 extends Input, I3 extends Input>(
    path: P,
    m1: Handler<E, NoInfer<P>, I1>,
    m2: Handler<E, NoInfer<P>, I2>,
    m3: Handler<E, NoInfer<P>, I3>,
    handler: Handler<E, NoInfer<P>, I1 & I2 & I3>
  ): Self;
  <P extends string>(path: P, ...handlers: Handler<E, NoInfer<P>, any>[]): Self;
}

export interface RegisterOptions<E extends Env = Env> {
  /** Extra path prefix in front of the controller's own. */
  prefix?: string;
  /** Middleware for every route of the controller (runs before the class / method `@Use`). */
  use?: InterceptorLike[];
}

export const defaultErrorHandler: ErrorHandler<any> = (err, c) => {
  if (err instanceof ValidationError) return c.json({ success: false, error: err.issues }, 400);
  if (err instanceof HTTPException) return err.getResponse();
  console.error(err);
  return c.text("Internal Server Error", 500);
};

export const defaultNotFound: NotFoundHandler<any> = (c) => c.text("404 Not Found", 404);

/** A Hono-style app: `app.get(path, ...handlers)`, `app.use(...)`, `app.register(controller)`, `app.fetch`. */
export class Kp<E extends Env = Env> {
  readonly get: RouteMethod<E, this>;
  readonly post: RouteMethod<E, this>;
  readonly put: RouteMethod<E, this>;
  readonly patch: RouteMethod<E, this>;
  readonly delete: RouteMethod<E, this>;
  readonly options: RouteMethod<E, this>;
  readonly all: RouteMethod<E, this>;

  #routes: Route[] = [];
  #onError: ErrorHandler<E> = defaultErrorHandler;
  #notFound: NotFoundHandler<E> = defaultNotFound;
  #providers = new Map<Function, Interceptor>();

  constructor(private readonly base = "") {
    const method =
      (m: string) =>
      (path: string, ...handlers: Handler<any, any, any>[]) =>
        this.on(m, path, ...handlers);
    this.get = method("GET") as RouteMethod<E, this>;
    this.post = method("POST") as RouteMethod<E, this>;
    this.put = method("PUT") as RouteMethod<E, this>;
    this.patch = method("PATCH") as RouteMethod<E, this>;
    this.delete = method("DELETE") as RouteMethod<E, this>;
    this.options = method("OPTIONS") as RouteMethod<E, this>;
    this.all = method(ALL) as RouteMethod<E, this>;
  }

  /** Register handlers for one method (or several, or "ALL"). */
  on(method: string | string[], path: string, ...handlers: Handler<E, any, any>[]): this {
    const full = joinPaths(this.base, path === "*" ? "/*" : path);
    for (const m of Array.isArray(method) ? method : [method]) {
      for (const handler of handlers) {
        this.#routes.push({ method: m.toUpperCase(), path: full, compiled: compilePath(full), handler });
      }
    }
    return this;
  }

  /** Middleware for every request (`use(mw)`) or a path (`use('/admin/*', mw)`). */
  use(...handlers: MiddlewareHandler<E, any>[]): this;
  use(path: string, ...handlers: MiddlewareHandler<E, any>[]): this;
  use(...args: (string | MiddlewareHandler<E, any>)[]): this {
    const path = typeof args[0] === "string" ? (args.shift() as string) : "/*";
    return this.on(ALL, path, ...(args as MiddlewareHandler<E, any>[]));
  }

  /** Mount another app's routes under `path`. */
  route(path: string, app: Kp<any>): this {
    for (const r of app.#routes) this.on(r.method, joinPaths(path, r.path), r.handler);
    return this;
  }

  /** Add the routes of `@Controller` instances. */
  register(controller: object, options?: RegisterOptions<E>): this;
  register(...controllers: object[]): this;
  register(...args: object[]): this {
    const last = args[args.length - 1];
    const options = args.length > 1 && last && !isControllerInstance(last) ? (args.pop() as RegisterOptions<E>) : {};
    for (const controller of args) {
      for (const r of controllerRoutes(controller)) {
        const path = joinPaths(options.prefix ?? "", r.path);
        const chain = [...(options.use ?? []), ...r.middleware].map((m) => this.#resolve(m));
        this.on(r.method, path, ...chain, r.handler);
      }
    }
    return this;
  }

  /** The instance @UseInterceptors(Token) uses. Call before register(). */
  provide<T extends Interceptor>(token: InterceptorClass<T>, instance: T): this {
    this.#providers.set(token, instance);
    return this;
  }

  #resolve(item: InterceptorLike): MiddlewareHandler<any, any> {
    if (isInterceptorClass(item)) {
      let instance = this.#providers.get(item);
      if (!instance) {
        if (item.length > 0) {
          throw new Error(`No instance for interceptor ${item.name}: call app.provide(${item.name}, instance) before app.register(...)`);
        }
        instance = new (item as unknown as new () => Interceptor)();
        this.#providers.set(item, instance);
      }
      const resolved = instance;
      return (c, next) => resolved.intercept(c, next);
    }
    if (typeof item === "object") return (c, next) => item.intercept(c, next);
    return item;
  }

  onError(handler: ErrorHandler<E>): this {
    this.#onError = handler;
    return this;
  }

  notFound(handler: NotFoundHandler<E>): this {
    this.#notFound = handler;
    return this;
  }

  /** Every registered route, for logging / debugging. */
  routes(): { method: string; path: string }[] {
    const seen = new Set<string>();
    return this.#routes
      .filter(({ method, path }) => !seen.has(`${method} ${path}`) && !!seen.add(`${method} ${path}`))
      .map(({ method, path }) => ({ method, path }));
  }

  /** The fetch handler: `(Request, env?) => Response`. */
  fetch = async (request: Request, env?: unknown): Promise<Response> => {
    const c = new Context<E>(request, env, this.#notFound);
    const isHead = request.method === "HEAD";
    const matches = this.#match(isHead ? "GET" : request.method, c.req.path);
    await this.#run(c, matches);
    const res = c.res;
    return isHead ? new Response(null, res) : res;
  };

  /** Test helper: `await app.request('/health')`. */
  request(input: string | Request, init?: RequestInit, env?: unknown): Promise<Response> {
    const req = input instanceof Request ? input : new Request(new URL(input, "http://localhost"), init);
    return this.fetch(req, env);
  }

  #match(method: string, path: string): { handler: Handler<any, any, any>; params: Record<string, string> }[] {
    const out = [];
    for (const r of this.#routes) {
      if (r.method !== ALL && r.method !== method) continue;
      const params = matchPath(r.compiled, path);
      if (params) out.push({ handler: r.handler, params });
    }
    return out;
  }

  /** Koa-style chain. An error is turned into a response at the layer that threw, so outer middleware still runs. */
  async #run(c: Context<E>, matches: { handler: Handler<any, any, any>; params: Record<string, string> }[]): Promise<void> {
    let index = -1;
    const dispatch = async (i: number): Promise<void> => {
      if (i <= index) throw new Error("next() called multiple times");
      index = i;
      const match = matches[i];
      if (!match) {
        if (!c.finalized) c.res = await this.#notFound(c);
        return;
      }
      c.req.setParams(match.params);
      try {
        const result = await match.handler(c, () => dispatch(i + 1));
        if (result instanceof Response) c.res = result;
        else if (!c.finalized) {
          throw new Error(`Handler for ${c.req.method} ${c.req.path} returned no Response (forgot \`return\` or \`await next()\`?)`);
        }
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        c.error = error;
        c.res = await this.#onError(error, c);
      }
    };
    await dispatch(0);
  }
}

export { METHODS };
