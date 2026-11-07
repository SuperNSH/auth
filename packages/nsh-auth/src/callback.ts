export interface CallbackResult {
  code: string | null;
  state: string | null;
  error: string | null;
  errorDescription: string | null;
}

/** Reads the redirect a provider sent back: query first, then the fragment (response_mode=fragment). */
export function parseCallback(url: string): CallbackResult {
  const result: CallbackResult = { code: null, state: null, error: null, errorDescription: null };
  const parsed = new URL(url);
  collect(result, parsed.searchParams);
  if (!result.code && !result.error && parsed.hash.length > 1) {
    collect(result, new URLSearchParams(parsed.hash.slice(1)));
  }
  return result;
}

function collect(result: CallbackResult, params: URLSearchParams): void {
  result.code ??= params.get("code");
  result.state ??= params.get("state");
  result.error ??= params.get("error");
  result.errorDescription ??= params.get("error_description");
}
