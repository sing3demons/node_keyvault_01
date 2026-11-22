import type { Context } from "./context.js";

/**
 * Variables every Context carries (`c.get` / `c.set`). Extend it once per app with module augmentation:
 *
 *   declare module "./common/kp/index.js" {
 *     interface ContextVariableMap { user: User }
 *   }
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface ContextVariableMap {}

/** Per-app typing: `Variables` for c.get / c.set, `Bindings` for c.env (what the server adapter passes). */
export type Env = { Variables?: object; Bindings?: object };

/** Validated data per target, filled by `validator(...)` middleware: `{ json: Body, query: Query }`. */
export type Input = Partial<Record<"json" | "form" | "query" | "param" | "header", unknown>>;

export type Variables<E extends Env> = ContextVariableMap & (E["Variables"] extends object ? E["Variables"] : {});
export type Bindings<E extends Env> = E["Bindings"] extends object ? E["Bindings"] : Record<string, unknown>;

export type Next = () => Promise<void>;

export type HandlerResult = Response | void | Promise<Response | void>;

/** A route handler or a middleware: return a Response, or call `await next()` to pass on. */
export type Handler<E extends Env = Env, P extends string = string, I extends Input = {}> = (
  c: Context<E, P, I>,
  next: Next
) => HandlerResult;

export type MiddlewareHandler<E extends Env = Env, P extends string = string, I extends Input = {}> = Handler<E, P, I>;

export type ErrorHandler<E extends Env = Env> = (err: Error, c: Context<E>) => Response | Promise<Response>;
export type NotFoundHandler<E extends Env = Env> = (c: Context<E>) => Response | Promise<Response>;

// ---------------------------------------------------------------- path params

type ParamName<S extends string> = S extends `${infer N}{${string}` ? N : S extends `${infer N}?` ? N : S;

type ExtractParams<P extends string> = P extends `${string}:${infer Rest}`
  ? Rest extends `${infer Name}/${infer Tail}`
    ? ParamName<Name> | ExtractParams<`/${Tail}`>
    : ParamName<Rest>
  : never;

/** `'/users/:id/posts/:postId'` -> `'id' | 'postId'`; a plain `string` path allows any key. */
export type ParamKeys<P extends string> = string extends P ? string : ExtractParams<P>;
