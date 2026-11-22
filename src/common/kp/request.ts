import type { Input, ParamKeys } from "./types.js";

export type BodyValue = string | File;

/** `c.req`: a read-only view of the incoming Request. The body is read once and cached, so every reader can be called again. */
export class KpRequest<P extends string = string, I extends Input = {}> {
  /** The runtime's own Request. */
  readonly raw: Request;
  readonly method: string;
  readonly url: string;
  readonly path: string;

  #url: URL;
  #params: Record<string, string> = {};
  #body?: Promise<ArrayBuffer>;
  #validated: Partial<Record<keyof Input, unknown>> = {};

  constructor(request: Request) {
    this.raw = request;
    this.method = request.method;
    this.url = request.url;
    this.#url = new URL(request.url);
    this.path = this.#url.pathname;
  }

  /** @internal set by the router for the handler that runs next */
  setParams(params: Record<string, string>): void {
    this.#params = params;
  }

  /** @internal set by validator() middleware */
  setValidated(target: keyof Input, value: unknown): void {
    this.#validated[target] = value;
  }

  // -------------------------------------------------------------- params / query / headers

  param(): Record<ParamKeys<P>, string>;
  param<K extends ParamKeys<P>>(key: K): string extends P ? string | undefined : string;
  param(key?: string): unknown {
    return key === undefined ? { ...this.#params } : this.#params[key];
  }

  /** All query values, first one per key. */
  query(): Record<string, string>;
  query(key: string): string | undefined;
  query(key?: string): unknown {
    const search = this.#url.searchParams;
    if (key !== undefined) return search.get(key) ?? undefined;
    const out: Record<string, string> = {};
    for (const [k, v] of search) if (!(k in out)) out[k] = v;
    return out;
  }

  /** Every value of repeated keys: `?tag=a&tag=b` -> `['a', 'b']`. */
  queries(): Record<string, string[]>;
  queries(key: string): string[] | undefined;
  queries(key?: string): unknown {
    const search = this.#url.searchParams;
    if (key !== undefined) {
      const all = search.getAll(key);
      return all.length ? all : undefined;
    }
    const out: Record<string, string[]> = {};
    for (const [k, v] of search) (out[k] ??= []).push(v);
    return out;
  }

  /** Header names are case-insensitive; `header()` returns them all, lower-cased. */
  header(): Record<string, string>;
  header(name: string): string | undefined;
  header(name?: string): unknown {
    if (name !== undefined) return this.raw.headers.get(name) ?? undefined;
    const out: Record<string, string> = {};
    this.raw.headers.forEach((v, k) => (out[k] = v));
    return out;
  }

  // -------------------------------------------------------------- body (cached)

  arrayBuffer(): Promise<ArrayBuffer> {
    return (this.#body ??= this.raw.arrayBuffer());
  }

  async text(): Promise<string> {
    return new TextDecoder().decode(await this.arrayBuffer());
  }

  async json<T = unknown>(): Promise<T> {
    return JSON.parse(await this.text()) as T;
  }

  /** multipart/form-data or application/x-www-form-urlencoded. */
  async formData(): Promise<FormData> {
    const contentType = this.header("content-type") ?? "";
    return new Response(await this.arrayBuffer(), { headers: { "content-type": contentType } }).formData();
  }

  /** Form body as an object (the last value wins for repeated keys, or `{ all: true }` for arrays); `{}` for other content types. */
  async parseBody(options: { all: true }): Promise<Record<string, BodyValue | BodyValue[]>>;
  async parseBody(options?: { all?: false }): Promise<Record<string, BodyValue>>;
  async parseBody(options: { all?: boolean } = {}): Promise<Record<string, BodyValue | BodyValue[]>> {
    const contentType = this.header("content-type") ?? "";
    if (!/^(multipart\/form-data|application\/x-www-form-urlencoded)/i.test(contentType)) return {};
    const out: Record<string, BodyValue | BodyValue[]> = {};
    for (const [key, value] of await this.formData()) {
      if (!options.all) {
        out[key] = value;
        continue;
      }
      const prev = out[key];
      out[key] = prev === undefined ? value : Array.isArray(prev) ? [...prev, value] : [prev, value];
    }
    return out;
  }

  // -------------------------------------------------------------- validator() output

  /** What `validator(target, schema)` checked. Only targets validated on this route compile. */
  valid<T extends keyof I>(target: T): I[T] {
    if (!(target in this.#validated)) throw new Error(`No validator ran for "${String(target)}" on this route`);
    return this.#validated[target as keyof Input] as I[T];
  }
}
