// kp: a small Hono-style HTTP framework with controller decorators, built on the Fetch API (Request / Response).
//
//   app.ts          Kp: routing, middleware chain, onError / notFound, register(@Controller instances)
//   context.ts      Ctx: c.req, response builders, c.get / c.set, safeQuery / safeBody / ... (Standard Schema)
//   request.ts      c.req: param, query, queries, header, json, text, formData, parseBody, valid
//   decorators.ts   @Controller, @Get / @Post / @Put / @Patch / @Delete / @Options / @All, @UseInterceptors (@Use)
//   validator.ts    validator(target, schema) middleware -> c.req.valid(target)
//   cookie.ts       getCookie / setCookie / deleteCookie
//   node.ts         serve (node:http), serveStatic, getConnInfo

export { Kp, defaultErrorHandler, defaultNotFound, type RegisterOptions } from "./app.js";
export { Context, type Ctx, type ValidateResult } from "./context.js";
export { getCookie, setCookie, deleteCookie, serializeCookie, type CookieOptions } from "./cookie.js";
export {
  Controller,
  Get,
  Post,
  Put,
  Patch,
  Delete,
  Options,
  All,
  Use,
  UseInterceptors,
  type Interceptor,
  type InterceptorClass,
  type InterceptorLike
} from "./decorators.js";
export { HTTPException, ValidationError, type ValidationTarget } from "./errors.js";
export { serve, serveStatic, getConnInfo, type NodeBindings, type ServeOptions, type ServeStaticOptions } from "./node.js";
export { KpRequest } from "./request.js";
export { formatIssues, type StandardSchemaV1, type Issue, type InferOutput } from "./standard-schema.js";
export type {
  ContextVariableMap,
  Env,
  ErrorHandler,
  Handler,
  Input,
  MiddlewareHandler,
  Next,
  NotFoundHandler,
  ParamKeys
} from "./types.js";
export { validator } from "./validator.js";
