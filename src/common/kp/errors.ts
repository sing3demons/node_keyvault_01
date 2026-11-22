import type { Issue } from "./standard-schema.js";

/** Throw from a handler to answer with `status` (or with a ready-made `res`). */
export class HTTPException extends Error {
  readonly res: Response | undefined;

  constructor(
    readonly status: number = 500,
    options: { message?: string; res?: Response; cause?: unknown } = {}
  ) {
    super(options.message ?? "", { cause: options.cause });
    this.res = options.res;
  }

  getResponse(): Response {
    return this.res ?? new Response(this.message, { status: this.status });
  }
}

export type ValidationTarget = "json" | "form" | "query" | "param" | "header";

/** A request part failed its schema. The default error handler answers 400 `{ success: false, error: issues }`. */
export class ValidationError extends Error {
  readonly status = 400;

  constructor(
    readonly target: ValidationTarget,
    readonly issues: ReadonlyArray<Issue>
  ) {
    super(`Invalid ${target}: ${issues.map((i) => i.message).join("; ")}`);
  }
}
