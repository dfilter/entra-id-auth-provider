type Success<T> = {
	data: T;
	error: null;
};

type Failure<E> = {
	data: null;
	error: E;
};

export type Result<T, E = Error> = Success<T> | Failure<E>;

export function tryCatchSync<TArgs extends unknown[], T, E = Error>(
	fn: (...args: TArgs) => T,
): (...args: TArgs) => Result<T, E> {
	return (...args: TArgs): Result<T, E> => {
		try {
			const data = fn(...args);
			return { data, error: null };
		} catch (error) {
			console.error(error);
			return { data: null, error: error as E };
		}
	};
}

export function tryCatch<TArgs extends unknown[], T, E = Error>(
	fn: (...args: TArgs) => Promise<T>,
): (...args: TArgs) => Promise<Result<T, E>> {
	return async (...args: TArgs): Promise<Result<T, E>> => {
		try {
			const data = await fn(...args);
			return { data, error: null };
		} catch (error) {
			console.error(error);
			return { data: null, error: error as E };
		}
	};
}

export class FetchError extends Error {
	constructor(response: Response, name: string, responseText: string) {
		super();
		const cause = `${response.statusText} - ${responseText}`;

		this.message = `HTTP Error ${response.status}: ${cause}`;
		this.cause = `${response.statusText} - ${responseText}`;
		this.name = `${name} FetchError`;
	}
}
