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
  wantsNonce: boolean;
  needsBroker: boolean;
  responseMode?: "form_post";
  /** Google revokes the refresh token, which kills its access tokens too. */
  revokeWithRefresh?: boolean;
}

export const DEFAULT_MOCK_BASE_URL = "http://127.0.0.1:8755";

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
        defaultScopes: ["openid", "email", "profile"],
        wantsNonce: true,
        needsBroker: false,
        revokeWithRefresh: true,
      };
    case "facebook":
      // The manual login flow exchanges the code with a GET carrying the verifier.
      return {
        id,
        authorizeUrl: "https://www.facebook.com/v21.0/dialog/oauth",
        tokenUrl: "https://graph.facebook.com/v21.0/oauth/access_token",
        tokenMethod: "GET",
        userinfoUrl: "https://graph.facebook.com/me?fields=id,name,email,picture",
        revokeUrl: "https://graph.facebook.com/v21.0/me/permissions",
        revokeMethod: "DELETE",
        jwksUrl: null,
        issuer: null,
        defaultScopes: ["public_profile", "email"],
        wantsNonce: false,
        needsBroker: false,
      };
    case "discord":
      return {
        id,
        authorizeUrl: "https://discord.com/api/v10/oauth2/authorize",
        tokenUrl: "https://discord.com/api/v10/oauth2/token",
        tokenMethod: "POST",
        userinfoUrl: "https://discord.com/api/v10/users/@me",
        revokeUrl: "https://discord.com/api/v10/oauth2/token/revoke",
        jwksUrl: "https://discord.com/api/v10/oauth2/jwks",
        issuer: "https://discord.com",
        defaultScopes: ["identify", "email"],
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
        defaultScopes: ["read:user", "user:email"],
        wantsNonce: false,
        needsBroker: true,
      };
    case "apple":
      // form_post is Apple's redirect rule; the token endpoint needs a client secret: broker only.
      return {
        id,
        authorizeUrl: "https://appleid.apple.com/auth/authorize",
        tokenUrl: null,
        tokenMethod: "POST",
        userinfoUrl: null,
        revokeUrl: null,
        jwksUrl: "https://appleid.apple.com/auth/keys",
        issuer: "https://appleid.apple.com",
        defaultScopes: ["name", "email"],
        wantsNonce: true,
        needsBroker: true,
        responseMode: "form_post",
      };
    case "microsoft":
      // A public client with PKCE needs no secret; the user comes from the id token's claims.
      return {
        id,
        authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        tokenMethod: "POST",
        userinfoUrl: null,
        revokeUrl: null,
        jwksUrl: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        issuer: null,
        defaultScopes: ["openid", "profile", "email", "offline_access", "User.Read"],
        wantsNonce: true,
        needsBroker: false,
      };
    case "x":
      return {
        id,
        authorizeUrl: "https://twitter.com/i/oauth2/authorize",
        tokenUrl: "https://api.twitter.com/2/oauth2/token",
        tokenMethod: "POST",
        userinfoUrl: "https://api.twitter.com/2/users/me",
        revokeUrl: "https://api.twitter.com/2/oauth2/revoke",
        jwksUrl: "https://api.twitter.com/2/oauth2/jwks",
        issuer: null,
        defaultScopes: ["users.read", "tweet.read", "offline_access"],
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
        wantsNonce: true,
        needsBroker: false,
      };
  }
}
