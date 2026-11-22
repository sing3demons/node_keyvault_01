// Standard Schema v1 (https://standardschema.dev): the shared interface zod, valibot, arktype, ... implement.
// Copied as types only (the spec asks implementers to copy rather than depend on a package).

export interface StandardSchemaV1<Input = unknown, Output = Input> {
  readonly "~standard": StandardSchemaV1.Props<Input, Output>;
}

export declare namespace StandardSchemaV1 {
  interface Props<Input = unknown, Output = Input> {
    readonly version: 1;
    readonly vendor: string;
    readonly validate: (value: unknown) => Result<Output> | Promise<Result<Output>>;
    readonly types?: Types<Input, Output> | undefined;
  }

  type Result<Output> = SuccessResult<Output> | FailureResult;

  interface SuccessResult<Output> {
    readonly value: Output;
    readonly issues?: undefined;
  }

  interface FailureResult {
    readonly issues: ReadonlyArray<Issue>;
  }

  interface Issue {
    readonly message: string;
    readonly path?: ReadonlyArray<PropertyKey | PathSegment> | undefined;
  }

  interface PathSegment {
    readonly key: PropertyKey;
  }

  interface Types<Input = unknown, Output = Input> {
    readonly input: Input;
    readonly output: Output;
  }

  type InferInput<S extends StandardSchemaV1> = NonNullable<S["~standard"]["types"]>["input"];
  type InferOutput<S extends StandardSchemaV1> = NonNullable<S["~standard"]["types"]>["output"];
}

export type Issue = StandardSchemaV1.Issue;
export type InferOutput<S extends StandardSchemaV1> = StandardSchemaV1.InferOutput<S>;

/** `a.b.0: message; c: message` */
export const formatIssues = (issues: ReadonlyArray<Issue>): string =>
  issues
    .map((i) => {
      const path = (i.path ?? []).map((p) => String(typeof p === "object" ? p.key : p)).join(".");
      return path ? `${path}: ${i.message}` : i.message;
    })
    .join("; ");
