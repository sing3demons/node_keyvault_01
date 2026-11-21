/** Generic HTTP error picked up by app.onError (reads `statusCode`). */
export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string
  ) {
    super(message);
  }
}

/** RFC 6749 §5.2 error response for the token / authorize endpoints. */
export class OAuthError extends Error {
  constructor(
    public readonly error:
      | "invalid_request"
      | "invalid_client"
      | "invalid_grant"
      | "unauthorized_client"
      | "unsupported_grant_type"
      | "unsupported_response_type"
      | "invalid_scope"
      | "access_denied",
    description: string,
    public readonly statusCode = 400
  ) {
    super(description);
  }
}
