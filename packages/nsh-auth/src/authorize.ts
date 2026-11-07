import type { ProviderConfig } from "./providers";

export interface AuthorizeOptions {
  provider: ProviderConfig;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  codeChallenge: string;
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
  params.set("code_challenge", options.codeChallenge);
  params.set("code_challenge_method", "S256");
  return `${provider.authorizeUrl}?${params.toString()}`;
}
