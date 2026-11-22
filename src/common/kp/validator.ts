import { readJson } from "./context.js";
import { ValidationError, type ValidationTarget } from "./errors.js";
import type { InferOutput, StandardSchemaV1 } from "./standard-schema.js";
import type { MiddlewareHandler } from "./types.js";

/**
 * Route middleware: validates one part of the request; the handler reads it with `c.req.valid(target)`.
 *
 *   app.post('/users', validator('json', NewUser), (c) => c.json(c.req.valid('json')))
 */
export function validator<T extends ValidationTarget, S extends StandardSchemaV1>(
  target: T,
  schema: S
): MiddlewareHandler<any, any, { [K in T]: InferOutput<S> }> {
  return async (c, next) => {
    const data = await read(c.req, target);
    const result = await schema["~standard"].validate(data);
    if (result.issues) throw new ValidationError(target, result.issues);
    c.req.setValidated(target, result.value);
    await next();
  };
}

function read(req: Parameters<MiddlewareHandler<any, any>>[0]["req"], target: ValidationTarget): unknown {
  switch (target) {
    case "json":
      return readJson(req);
    case "form":
      return req.parseBody();
    case "query":
      return req.query();
    case "param":
      return req.param();
    case "header":
      return req.header();
  }
}
