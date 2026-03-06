import type { AuthProviderCallbacks, ErrorProps, Result } from "./types";

export function tryCatch<TArgs extends unknown[], T, E extends Error>(
  fn: (...args: TArgs) => Promise<T>,
  callbacks?: AuthProviderCallbacks,
): (...args: TArgs) => Promise<Result<T, E>> {
  return async (...args: TArgs): Promise<Result<T, E>> => {
    try {
      const data = await fn(...args);
      return { data, error: null };
    } catch (error) {
      callbacks?.onError?.(error as E);
      return { data: null, error: error as E };
    }
  };
}

export function tryCatchSync<TArgs extends unknown[], T, E extends Error>(
  fn: (...args: TArgs) => T,
  callbacks?: AuthProviderCallbacks,
): (...args: TArgs) => Result<T, E> {
  return (...args: TArgs): Result<T, E> => {
    try {
      const data = fn(...args);
      return { data, error: null };
    } catch (error) {
      callbacks?.onError?.(error as E);
      return { data: null, error: error as E };
    }
  };
}

export class AcquireTokenOnBehalfOfError extends Error implements ErrorProps {
  name = "AcquireTokenOnBehalfOfError";
  message: string;
  body: string;
  status: number;
  statusText: string;
  props: ErrorProps["props"];

  constructor({ message, body, status, statusText, props }: ErrorProps) {
    super(message);
    this.message = message;
    this.body = body;
    this.status = status;
    this.statusText = statusText;
    this.props = props;
  }
}

export class AcquireTokenByClientCredentialError
  extends Error
  implements ErrorProps
{
  name = "AcquireTokenByClientCredentialError";
  message: string;
  body: string;
  status: number;
  statusText: string;
  props: ErrorProps["props"];

  constructor({ message, body, status, statusText, props }: ErrorProps) {
    super(message);
    this.message = message;
    this.body = body;
    this.status = status;
    this.statusText = statusText;
    this.props = props;
  }
}
