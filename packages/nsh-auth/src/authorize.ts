import type { ProviderConfig } from "./providers";

export interface AuthorizeOptions {
  provider: ProviderConfig;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  /** S256 challenge; omitted for providers without PKCE (Apple). */
  codeChallenge?: string;
  state: string;
  nonce?: string;
}

export function buildAuthorizeUrl(options: AuthorizeOptions): string {
  const provider = options.provider;
  const params = new URLSearchParams();
  params.set("response_type", "code");
  params.set("client_id", options.clientId);
  params.set("redirect_uri", options.redirectUri);
  params.set("scope", options.scopes.join(" "));
  params.set("state", options.state);
  if (provider.wantsNonce && options.nonce) params.set("nonce", options.nonce);
  if (provider.responseMode) params.set("response_mode", provider.responseMode);
  if (provider.usePkce && options.codeChallenge) {
    params.set("code_challenge", options.codeChallenge);
    params.set("code_challenge_method", "S256");
  }
  for (const [key, value] of Object.entries(provider.authorizeExtras ?? {})) params.set(key, value);
  return `${provider.authorizeUrl}?${params.toString()}`;
}
