/** Date `ms` milliseconds from now — for expiresAt fields. */
export const expiresIn = (ms: number): Date => new Date(Date.now() + ms);

/** Message of a caught value, which may not be an Error. */
export const errorMessage = (error: unknown): string => (error instanceof Error ? error.message : String(error));
