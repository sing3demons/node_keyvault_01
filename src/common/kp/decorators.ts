// Controller decorators (TC39 standard decorators: no `experimentalDecorators` / reflect-metadata needed).
//
//   @Controller('/users')
//   @UseInterceptors(Bearer, logger)          // interceptor classes and/or plain middleware
//   export class UserController {
//     constructor(private readonly service: UserService) {}
//
//     @Get('/')
//     list(c: Ctx) { return c.json(this.service.list(c.safeQuery(UserQuery).limit)) }
//
//     @Post('/')
//     @UseInterceptors(requireRole('admin'))
//     async create(c: Ctx) { return c.json(await this.service.create(await c.safeBody(NewUser)), 201) }
//   }
//
//   app.provide(Bearer, new Bearer(oauth))     // instance for the Bearer token (before register)
//   app.register(new UserController(service))
//
// An interceptor class with no constructor arguments needs no provide(): the app creates one itself.

import { joinPaths } from "./router.js";
import type { Context } from "./context.js";
import type { Handler, HandlerResult, MiddlewareHandler, Next } from "./types.js";

/** Class-based middleware: `intercept` gets the context and `next`, like a middleware function. */
export interface Interceptor {
  intercept(c: Context<any, any, any>, next: Next): HandlerResult;
}

/** An interceptor class used as a token; the instance comes from `app.provide(Token, instance)`. */
export type InterceptorClass<T extends Interceptor = Interceptor> = abstract new (...args: any[]) => T;

/** What @UseInterceptors / register({ use }) accept: a middleware function, an interceptor instance, or its class. */
export type InterceptorLike = MiddlewareHandler<any, any, any> | Interceptor | InterceptorClass;

export const isInterceptorClass = (value: unknown): value is InterceptorClass =>
  typeof value === "function" && typeof (value as { prototype?: { intercept?: unknown } }).prototype?.intercept === "function";

type AnyClass = abstract new (...args: any[]) => any;
type Method = (c: any, ...rest: any[]) => unknown;

interface RouteMeta {
  method: string;
  path: string;
}

const controllers = new WeakMap<Function, { prefix: string }>();
const classMiddleware = new WeakMap<Function, InterceptorLike[]>();
const methodRoutes = new WeakMap<Function, RouteMeta[]>();
const methodMiddleware = new WeakMap<Function, InterceptorLike[]>();

/** Marks a class as a controller; its routes sit under `prefix`. */
export function Controller(prefix = "/") {
  return <T extends AnyClass>(target: T, _context: ClassDecoratorContext<T>): void => {
    controllers.set(target, { prefix });
  };
}

function routeDecorator(method: string) {
  return (path = "/") =>
    <T extends Method>(target: T, context: ClassMethodDecoratorContext<unknown, T>): void => {
      if (context.static || context.private) throw new TypeError(`@${method} needs a public instance method`);
      const list = methodRoutes.get(target) ?? [];
      list.push({ method, path });
      methodRoutes.set(target, list);
    };
}

export const Get = routeDecorator("GET");
export const Post = routeDecorator("POST");
export const Put = routeDecorator("PUT");
export const Patch = routeDecorator("PATCH");
export const Delete = routeDecorator("DELETE");
export const Options = routeDecorator("OPTIONS");
export const All = routeDecorator("ALL");

/**
 * Interceptors / middleware for every route of a class, or for one method. Run in the order written
 * (class ones before method ones).
 */
export function UseInterceptors(...middleware: InterceptorLike[]) {
  return (target: Function, context: ClassDecoratorContext | ClassMethodDecoratorContext): void => {
    const store = context.kind === "class" ? classMiddleware : methodMiddleware;
    // decorators apply bottom-up, so prepend to keep the written order
    store.set(target, [...middleware, ...(store.get(target) ?? [])]);
  };
}

/** Same as UseInterceptors. */
export const Use = UseInterceptors;

export interface ControllerRoute {
  method: string;
  path: string;
  middleware: InterceptorLike[];
  handler: Handler<any, any, any>;
}

/** Finds the controller metadata of an instance's class (or a base class). */
function controllerClass(instance: object): Function | undefined {
  for (let proto = Object.getPrototypeOf(instance); proto && proto !== Object.prototype; proto = Object.getPrototypeOf(proto)) {
    if (controllers.has(proto.constructor)) return proto.constructor;
  }
  return undefined;
}

export const isControllerInstance = (value: object): boolean => controllerClass(value) !== undefined;

/** The routes of a `@Controller` instance, with handlers bound to it. */
export function controllerRoutes(instance: object): ControllerRoute[] {
  const ctor = controllerClass(instance);
  if (!ctor) throw new TypeError(`${instance.constructor?.name ?? "value"} is not a @Controller class instance`);
  const { prefix } = controllers.get(ctor)!;
  const shared = classMiddleware.get(ctor) ?? [];

  const routes: ControllerRoute[] = [];
  const seen = new Set<string>();
  for (let proto = Object.getPrototypeOf(instance); proto && proto !== Object.prototype; proto = Object.getPrototypeOf(proto)) {
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (name === "constructor" || seen.has(name)) continue;
      seen.add(name);
      const fn = Object.getOwnPropertyDescriptor(proto, name)?.value;
      if (typeof fn !== "function") continue;
      const metas = methodRoutes.get(fn);
      if (!metas) continue;
      const handler: Handler<any, any, any> = (c, next) => fn.call(instance, c, next);
      for (const meta of metas) {
        routes.push({
          method: meta.method,
          path: joinPaths(prefix, meta.path),
          middleware: [...shared, ...(methodMiddleware.get(fn) ?? [])],
          handler
        });
      }
    }
  }
  return routes;
}
