export type ProviderId =
  | "google"
  | "facebook"
  | "discord"
  | "github"
  | "apple"
  | "microsoft"
  | "x"
  | "oidc"
  | "mock";

export interface ProviderConfig {
  id: ProviderId;
  authorizeUrl: string;
  /** null: the client secret belongs server-side, so the exchange goes through `brokerUrl`. */
  tokenUrl: string | null;
  tokenMethod: "GET" | "POST";
  userinfoUrl: string | null;
  revokeUrl: string | null;
  revokeMethod?: "DELETE";
  jwksUrl: string | null;
  /** id-token `iss` to enforce; null: the issuer varies (Microsoft tenants), so it is not checked. */
  issuer: string | null;
  defaultScopes: string[];
  /** S256 PKCE on the authorize leg; false where the provider has none (Apple). */
  usePkce: boolean;
  wantsNonce: boolean;
  needsBroker: boolean;
  responseMode?: "form_post";
  /** Fixed authorize parameters the provider documents (Google's refresh consent). */
  authorizeExtras?: Record<string, string>;
  /** Google revokes the refresh token, which kills its access tokens too. */
  revokeWithRefresh?: boolean;
}

export const DEFAULT_MOCK_BASE_URL = "http://127.0.0.1:8755";

// Per-provider facts from fixtures/provider-catalog.json and docs/providers.md (a)-(d).
export function providerConfig(id: ProviderId, mockBaseUrl: string = DEFAULT_MOCK_BASE_URL): ProviderConfig {
  switch (id) {
    case "google":
      return {
        id,
        authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenUrl: "https://oauth2.googleapis.com/token",
        tokenMethod: "POST",
        userinfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
        revokeUrl: "https://oauth2.googleapis.com/revoke",
        jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
        issuer: "https://accounts.google.com",
        defaultScopes: ["openid", "profile", "email"],
        usePkce: true,
        wantsNonce: true,
        needsBroker: false,
        authorizeExtras: { access_type: "offline", prompt: "consent" },
        revokeWithRefresh: true,
      };
    case "facebook":
      // The OIDC code flow with PKCE for public clients: the verifier makes the
      // secret optional, and the ID token rides on the openid scope. The classic
      // secret-bearing manual flow stays behind the broker.
      return {
        id,
        authorizeUrl: "https://www.facebook.com/v27.0/dialog/oauth",
        tokenUrl: "https://graph.facebook.com/v27.0/oauth/access_token",
        tokenMethod: "GET",
        userinfoUrl: "https://graph.facebook.com/me?fields=id,name,email,picture",
        revokeUrl: "https://graph.facebook.com/v27.0/me/permissions",
        revokeMethod: "DELETE",
        jwksUrl: "https://www.facebook.com/.well-known/oauth/openid/jwks/",
        issuer: "https://www.facebook.com",
        defaultScopes: ["openid", "public_profile", "email"],
        usePkce: true,
        wantsNonce: true,
        needsBroker: false,
      };
    case "discord":
      return {
        id,
        authorizeUrl: "https://discord.com/oauth2/authorize",
        tokenUrl: "https://discord.com/api/oauth2/token",
        tokenMethod: "POST",
        userinfoUrl: "https://discord.com/api/users/@me",
        revokeUrl: "https://discord.com/api/oauth2/token/revoke",
        jwksUrl: "https://discord.com/api/oauth2/keys",
        issuer: "https://discord.com",
        defaultScopes: ["identify", "email"],
        usePkce: true,
        wantsNonce: false,
        needsBroker: false,
      };
    case "github":
      // The web flow still needs a client secret at the token endpoint: broker only.
      return {
        id,
        authorizeUrl: "https://github.com/login/oauth/authorize",
        tokenUrl: null,
        tokenMethod: "POST",
        userinfoUrl: "https://api.github.com/user",
        revokeUrl: null,
        jwksUrl: null,
        issuer: null,
        defaultScopes: ["read:user", "user:email", "offline_access"],
        usePkce: true,
        wantsNonce: false,
        needsBroker: true,
      };
    case "apple":
      // The client_secret JWT is Apple's client authentication — the catalog has
      // no PKCE for it. form_post is Apple's redirect rule; broker only.
      return {
        id,
        authorizeUrl: "https://appleid.apple.com/auth/authorize",
        tokenUrl: null,
        tokenMethod: "POST",
        userinfoUrl: null,
        revokeUrl: null,
        jwksUrl: "https://appleid.apple.com/auth/keys",
        issuer: "https://appleid.apple.com",
        defaultScopes: ["openid", "name", "email"],
        usePkce: false,
        wantsNonce: true,
        needsBroker: true,
        responseMode: "form_post",
      };
    case "microsoft":
      // A public client with PKCE needs no secret; identity also comes from Graph's OIDC userinfo.
      return {
        id,
        authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        tokenMethod: "POST",
        userinfoUrl: "https://graph.microsoft.com/oidc/userinfo",
        revokeUrl: null,
        jwksUrl: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        issuer: null,
        defaultScopes: ["openid", "profile", "email", "offline_access", "User.Read"],
        usePkce: true,
        wantsNonce: true,
        needsBroker: false,
      };
    case "x":
      return {
        id,
        authorizeUrl: "https://x.com/i/oauth2/authorize",
        tokenUrl: "https://api.x.com/2/oauth2/token",
        tokenMethod: "POST",
        userinfoUrl: "https://api.x.com/2/users/me",
        revokeUrl: "https://api.x.com/2/oauth2/revoke",
        jwksUrl: null,
        issuer: null,
        defaultScopes: ["users.read", "tweet.read", "offline.access"],
        usePkce: true,
        wantsNonce: false,
        needsBroker: false,
      };
    case "oidc":
    case "mock":
      // Route tables of the sandbox mock server (tools/mock-oauth
      // providers.mjs), where "oidc" is its own realm next to the plain mock.
      // Issuers follow each realm's discovery document.
      return {
        id,
        authorizeUrl: `${mockBaseUrl}/${id}/authorize`,
        tokenUrl: `${mockBaseUrl}/${id}/token`,
        tokenMethod: "POST",
        userinfoUrl: `${mockBaseUrl}/${id}/userinfo`,
        revokeUrl: `${mockBaseUrl}/${id}/revoke`,
        jwksUrl: `${mockBaseUrl}/${id}/.well-known/jwks.json`,
        issuer: `${mockBaseUrl}/${id}`,
        defaultScopes: ["openid", "profile", "email", "offline_access"],
        usePkce: true,
        wantsNonce: true,
        needsBroker: false,
      };
  }
}
