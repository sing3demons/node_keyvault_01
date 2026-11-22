// HTTP boundary helpers: one error format for every endpoint, and request parsing with zod.
//
// Every error response uses the OAuth 2.0 shape (RFC 6749 §5.2):
//   { "error": "<code>", "error_description": "<human readable>" }

import type { z } from "zod";
import { formatIssues, ValidationError, type Context, type ErrorHandler, type NotFoundHandler } from "../common/kp/index.js";
import { errorMessage } from "./util.js";

export interface ErrorBody {
  error: string;
  error_description: string;
}

/** Default `error` code per status: RFC 6749 / RFC 6750 codes where one fits, plain names otherwise. */
const DEFAULT_ERROR_CODES: Partial<Record<number, string>> = {
  400: "invalid_request",
  401: "invalid_token",
  403: "insufficient_scope",
  404: "not_found",
  409: "conflict",
  500: "server_error",
  503: "temporarily_unavailable"
};

const errorCodeFor = (status: number): string =>
  DEFAULT_ERROR_CODES[status] ?? (status >= 500 ? "server_error" : "invalid_request");

/** Error with an HTTP status and an OAuth-style `error` code (defaults from the status). */
export class HttpError extends Error {
  readonly error: string;

  constructor(
    readonly statusCode: number,
    description: string,
    error?: string
  ) {
    super(description);
    this.error = error ?? errorCodeFor(statusCode);
  }
}

const isErrorStatus = (value: unknown): value is number =>
  typeof value === "number" && value >= 400 && value < 600;

/**
 * app.onError: HttpError as-is; failed c.safeBody / c.safeParam / validator() are 400 invalid_request;
 * upstream 4xx (e.g. Azure RestError) keep their status; anything else is a 500.
 */
export const errorHandler: ErrorHandler = (err, c) => {
  if (err instanceof ValidationError) {
    return c.json<ErrorBody>({ error: "invalid_request", error_description: formatIssues(err.issues) }, 400);
  }
  if (err instanceof HttpError) {
    return c.json<ErrorBody>({ error: err.error, error_description: err.message }, err.statusCode);
  }
  const status = (err as { statusCode?: unknown }).statusCode;
  if (isErrorStatus(status) && status < 500) {
    return c.json<ErrorBody>({ error: errorCodeFor(status), error_description: errorMessage(err) }, status);
  }
  console.error(err);
  const code = isErrorStatus(status) ? status : 500;
  return c.json<ErrorBody>({ error: errorCodeFor(code), error_description: "Internal server error" }, code);
};

export const notFoundHandler: NotFoundHandler = (c) =>
  c.json<ErrorBody>({ error: "not_found", error_description: `No route for ${c.req.method} ${c.req.path}` }, 404);

export const formatZodError = (error: z.ZodError): string =>
  error.issues.map((i) => (i.path.length ? `${i.path.join(".")}: ${i.message}` : i.message)).join("; ");

/** Validates input against a schema; failures become 400 with a readable message. */
export function parse<S extends z.ZodType>(schema: S, input: unknown): z.output<S> {
  const result = schema.safeParse(input);
  if (!result.success) throw new HttpError(400, formatZodError(result.error));
  return result.data;
}

/** Reads the JSON body and validates it. */
export async function parseJsonBody<S extends z.ZodType>(c: Context, schema: S): Promise<z.output<S>> {
  const body: unknown = await c.req.json().catch(() => {
    throw new HttpError(400, "Request body must be valid JSON");
  });
  return parse(schema, body);
}
