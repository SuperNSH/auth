// Provider behavior catalog: real response shapes, quirks and error styles.
// Sandboxing rule: every realm/issuer/token string says "nsh-sandbox"; only the
// field names and value formats imitate the real providers.

export const SANDBOX_EMAIL = "sandbox.user@nsh-auth.invalid";
export const SANDBOX_NAME = "Sandbox User";

export const SANDBOX_PROFILE = {
  google: {
    sub: "nsh-sandbox-google-user-0001",
    name: SANDBOX_NAME, given_name: "Sandbox", family_name: "User",
  },
  facebook: { id: "nsh-sandbox-fb-user-0001", name: SANDBOX_NAME },
  discord: { id: "nsh-sandbox-discord-user-0001", username: "nsh_sandbox_user", globalName: SANDBOX_NAME },
  github: { login: "nsh-sandbox-user", id: 1000000001, name: SANDBOX_NAME },
  apple: { sub: "000000.nsh-sandbox.0000", name: SANDBOX_NAME, firstName: "Sandbox", lastName: "User" },
  microsoft: { sub: "00000000-0000-4000-8000-000000000001", name: SANDBOX_NAME },
  x: { id: "1900000000000000001", name: SANDBOX_NAME, username: "nsh_sandbox_user" },
  oidc: { sub: "nsh-sandbox-oidc-user-0001", name: SANDBOX_NAME, given_name: "Sandbox", family_name: "User" },
  mock: { sub: "nsh-sandbox-mock-user-0001", name: SANDBOX_NAME, given_name: "Sandbox", family_name: "User" },
};

const REASON_TEXT = {
  unknown_code: ["invalid_grant", "Invalid authorization code."],
  expired_code: ["invalid_grant", "Authorization code expired."],
  code_already_used: ["invalid_grant", "Code was already redeemed."],
  client_mismatch: ["invalid_grant", "client_id does not match the authorization request."],
  redirect_mismatch: ["invalid_grant", "redirect_uri does not match the authorization request."],
  pkce_missing: ["invalid_grant", "code_verifier is required for this authorization code."],
  pkce_mismatch: ["invalid_grant", "Code challenge does not match the code_verifier."],
  unknown_refresh: ["invalid_grant", "Invalid refresh token."],
  revoked_refresh: ["invalid_grant", "Token has been expired or revoked."],
  refresh_reused: ["invalid_grant", "Refresh token has already been used; the token family was revoked."],
  refresh_required: ["invalid_request", "refresh_token parameter is required."],
  fb_token_unknown: ["invalid_grant", "Invalid fb_exchange_token value."],
  invalid_client: ["invalid_client", "client_secret is missing or empty."],
  unsupported_grant: ["unsupported_grant_type", "grant_type is not supported."],
  invalid_request: ["invalid_request", "The request is missing a required parameter or is malformed."],
  wrong_content_type: ["invalid_request", "Only application/x-www-form-urlencoded bodies are accepted."],
  redirect_required: ["invalid_request", "redirect_uri is required."],
};

// AADSTS codes for the Microsoft flavor (real code numbers, sandbox text).
const AADSTS = {
  unknown_code: [70000, "The provided value for the authorization code is invalid."],
  expired_code: [70008, "The authorization code expired."],
  code_already_used: [54005, "OAuth2 Authorization code was already redeemed."],
  client_mismatch: [7000218, "The client_id does not match the authorization request."],
  redirect_mismatch: [50011, "The redirect URI does not match the redirect URI configured for the application."],
  pkce_missing: [50173, "The code_verifier is required for this authorization code."],
  pkce_mismatch: [50173, "The provided code_verifier does not match the code_challenge."],
  unknown_refresh: [70008, "The refresh token is invalid."],
  revoked_refresh: [70008, "The refresh token has been revoked."],
  refresh_reused: [70008, "The refresh token has already been used; the token family was revoked."],
  refresh_required: [900231, "refresh_token parameter is required."],
  invalid_client: [7000218, "client_secret is missing or empty."],
  unsupported_grant: [900232, "grant_type is not supported."],
  invalid_request: [900232, "The request is missing a required parameter or is malformed."],
  wrong_content_type: [900232, "Only application/x-www-form-urlencoded bodies are accepted."],
  redirect_required: [50011, "redirect_uri is required."],
};

const FACEBOOK_MSG = {
  unknown_code: "Error validating authorization code. Please ensure that your redirect_uri is identical to the one you used when requesting the authorization code.",
  expired_code: "Error validating authorization code: the code has expired.",
  code_already_used: "Error validating authorization code: the code has already been used.",
  client_mismatch: "Error validating authorization code: the client_id does not match the authorization request.",
  redirect_mismatch: "Error validating authorization code. Please ensure that your redirect_uri is identical to the one you used when requesting the authorization code.",
  pkce_missing: "Error validating authorization code: code_verifier is required for this code.",
  pkce_mismatch: "Error validating authorization code: code_verifier does not match the code_challenge.",
  unknown_refresh: "Invalid OAuth access token.",
  revoked_refresh: "Invalid OAuth access token: the token has been revoked.",
  refresh_reused: "Invalid OAuth access token: the token has already been exchanged.",
  fb_token_unknown: "Invalid OAuth access token.",
  invalid_client: "Invalid app credentials.",
  unsupported_grant: "Unsupported grant type.",
  invalid_request: "The request is missing a required parameter or is malformed.",
  wrong_content_type: "Only application/x-www-form-urlencoded bodies are accepted.",
  redirect_required: "redirect_uri is required.",
};

function traceId() {
  return "nsh-sandbox-fbtrace-" + Math.random().toString(36).slice(2, 10);
}

// Builds a provider-shaped token-error body for a canonical sandbox reason.
export function tokenErrorBody(prov, reason) {
  const suffix = ` (sandbox_reason: ${reason})`;
  switch (prov.errorStyle) {
    case "nested": {
      // Facebook Graph API error envelope.
      const tokenReasons = ["unknown_refresh", "revoked_refresh", "refresh_reused", "fb_token_unknown"];
      const code = tokenReasons.includes(reason) ? 190 : reason === "invalid_request" || reason === "wrong_content_type" ? 100 : 400;
      return {
        error: {
          message: (FACEBOOK_MSG[reason] ?? FACEBOOK_MSG.invalid_request) + (tokenReasons.includes(reason) ? "" : suffix),
          type: "OAuthException",
          code,
          error_subcode: tokenReasons.includes(reason) ? 463 : undefined,
          fbtrace_id: traceId(),
        },
      };
    }
    case "aadsts": {
      const [code, text] = AADSTS[reason] ?? AADSTS.invalid_request;
      return {
        error: REASON_TEXT[reason]?.[0] ?? "invalid_grant",
        error_description: `AADSTS${code}: ${text}${suffix}`,
        error_codes: [code],
        timestamp: new Date().toISOString(),
        trace_id: "nsh-sandbox-trace",
        correlation_id: "nsh-sandbox-correlation",
      };
    }
    case "github": {
      // GitHub reports token errors in-band with HTTP 200 (observed quirk).
      const refreshReasons = ["unknown_refresh", "revoked_refresh", "refresh_reused", "refresh_required"];
      const map = refreshReasons.includes(reason)
        ? ["bad_refresh_token", "The refresh token passed is incorrect or expired.", "https://docs.github.com/apps/oauth-apps/troubleshooting-oauth-app-errors/#bad-refresh-token"]
        : ["bad_verification_code", "The code passed is incorrect or expired.", "https://docs.github.com/apps/oauth-apps/troubleshooting-oauth-app-errors/#bad-verification-code"];
      const flat = ["invalid_request", "wrong_content_type"].includes(reason)
        ? { error: "invalid_request", error_description: REASON_TEXT[reason][1] + suffix }
        : { error: map[0], error_description: map[1] + suffix, error_uri: map[2] };
      return flat;
    }
    case "terse": {
      // Apple is terse but includes error_description on some codes; sandbox keeps it.
      const [error, text] = REASON_TEXT[reason] ?? REASON_TEXT.invalid_request;
      return { error, error_description: text + suffix };
    }
    default: {
      const [error, text] = REASON_TEXT[reason] ?? REASON_TEXT.invalid_request;
      return { error, error_description: text + suffix };
    }
  }
}

const claimsBase = (prov, base, clientId) => ({
  iss: `${base}/${prov}`,
  aud: clientId,
  email: SANDBOX_EMAIL,
  iat: Math.floor(Date.now() / 1000),
});

export function splitScopes(sep, raw) {
  return (raw ?? "").split(sep).map((s) => s.trim()).filter(Boolean);
}

export const providers = {
  google: {
    id: "google",
    realm: "nsh-auth sandbox (not Google)",
    errorStyle: "flat",
    errorStatus: 400,
    scopeSeparator: " ",
    defaultScope: "openid email profile",
    authorizeMode: "query",
    responseModes: ["query"],
    requiresState: false,
    allowCodeIdToken: false,
    tokenMethods: ["POST"],
    formOnly: false,
    contentNegotiation: false,
    requireRedirectAtToken: true,
    requireClientSecret: false,
    refreshKind: "refresh_token",
    routes: {
      authorize: "/google/o/oauth2/v2/auth",
      token: "/google/token",
      userinfo: "/google/userinfo",
      revoke: "/google/revoke",
      jwks: "/google/.well-known/jwks.json",
      discovery: "/google/.well-known/openid-configuration",
    },
    revokeMethods: ["POST", "GET"],
    revokeSuccess: { status: 200, body: null },
    refreshIssuedWhen: ({ authorizeParams: q }) =>
      q.access_type === "offline" || String(q.prompt ?? "").includes("consent"),
    idTokenIssuedWhen: ({ scopes }) => scopes.includes("openid"),
    tokenExpiresIn: 3599,
    tokenBody: (ctx) => {
      const body = {
        access_token: ctx.access,
        expires_in: 3599,
        refresh_token: ctx.refresh,
        scope: ctx.scopesRaw,
        token_type: "Bearer",
      };
      if (ctx.idToken) body.id_token = ctx.idToken;
      // Google omits refresh_token entirely when offline access was not granted.
      if (!ctx.refresh) delete body.refresh_token;
      return body;
    },
    idTokenClaims: (ctx) => ({
      ...claimsBase("google", ctx.base, ctx.clientId),
      azp: ctx.clientId,
      sub: SANDBOX_PROFILE.google.sub,
      email_verified: true,
      name: SANDBOX_PROFILE.google.name,
      given_name: SANDBOX_PROFILE.google.given_name,
      family_name: SANDBOX_PROFILE.google.family_name,
      picture: `${ctx.base}/avatar.png`,
    }),
    userinfoBody: (ctx) => ({
      sub: SANDBOX_PROFILE.google.sub,
      name: SANDBOX_PROFILE.google.name,
      given_name: SANDBOX_PROFILE.google.given_name,
      family_name: SANDBOX_PROFILE.google.family_name,
      picture: `${ctx.base}/avatar.png`,
      email: SANDBOX_EMAIL,
      email_verified: true,
    }),
    unauthorized: {
      status: 401,
      headers: { "WWW-Authenticate": 'Bearer realm="nsh-auth sandbox (not Google)", error="invalid_token"' },
      body: { error: "invalid_token", error_description: "Invalid value for 'access_token'. (sandbox_reason: invalid_token)" },
    },
    discoveryDoc: (base, r) => ({
      issuer: `${base}/google`,
      authorization_endpoint: base + r.authorize,
      token_endpoint: base + r.token,
      userinfo_endpoint: base + r.userinfo,
      revocation_endpoint: base + r.revoke,
      jwks_uri: base + r.jwks,
      scopes_supported: ["openid", "email", "profile"],
      response_types_supported: ["code", "token"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256", "plain"],
      claims_supported: ["aud", "email", "email_verified", "exp", "given_name", "family_name", "iat", "iss", "name", "picture", "sub"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    }),
  },

  facebook: {
    id: "facebook",
    realm: "nsh-auth sandbox (not Facebook)",
    errorStyle: "nested",
    errorStatus: 400,
    scopeSeparator: ",",
    defaultScope: "public_profile,email",
    authorizeMode: "query",
    responseModes: ["query"],
    requiresState: false,
    allowCodeIdToken: false,
    tokenMethods: ["POST", "GET"], // Graph accepts the token call as GET with query-string params
    formOnly: false,
    contentNegotiation: false,
    requireRedirectAtToken: false,
    requireClientSecret: false,
    refreshKind: "fb_exchange_token",
    routes: {
      authorize: "/facebook/v21.0/dialog/oauth",
      token: "/facebook/v21.0/oauth/access_token",
      userinfo: "/facebook/me",
      debugToken: "/facebook/debug_token",
      revoke: "/facebook/permissions",
      jwks: "/facebook/.well-known/jwks.json",
    },
    revokeMethods: ["DELETE", "POST"],
    revokeSuccess: { status: 200, body: { success: true } },
    refreshIssuedWhen: () => false,
    idTokenIssuedWhen: ({ scopes }) => scopes.includes("openid"),
    tokenExpiresIn: 5183944,
    tokenBody: (ctx) => {
      const body = { access_token: ctx.access, token_type: "bearer", expires_in: 5183944 };
      if (ctx.idToken) body.id_token = ctx.idToken;
      return body;
    },
    idTokenClaims: (ctx) => ({
      ...claimsBase("facebook", ctx.base, ctx.clientId),
      sub: SANDBOX_PROFILE.facebook.id,
      jti: "nsh-sandbox-fb-jti",
      email_verified: true,
      picture: `${ctx.base}/avatar.png`,
    }),
    userinfoBody: (ctx) => {
      const body = {
        id: SANDBOX_PROFILE.facebook.id,
        name: SANDBOX_PROFILE.facebook.name,
        picture: { data: { height: 200, width: 200, is_silhouette: false, url: `${ctx.base}/avatar.png` } },
      };
      if (ctx.scopes.includes("email")) body.email = SANDBOX_EMAIL;
      return body;
    },
    unauthorized: {
      status: 400,
      body: null, // built lazily in server.mjs to refresh fbtrace_id per response
    },
    debugToken: true,
    discoveryDoc: null,
  },

  discord: {
    id: "discord",
    realm: "nsh-auth sandbox (not Discord)",
    errorStyle: "flat",
    errorStatus: 400,
    scopeSeparator: " ",
    defaultScope: "identify email",
    authorizeMode: "query",
    responseModes: ["query"],
    requiresState: false,
    allowCodeIdToken: false,
    tokenMethods: ["POST"],
    formOnly: true, // Discord token endpoint rejects non-urlencoded bodies
    contentNegotiation: false,
    requireRedirectAtToken: false,
    requireClientSecret: false,
    refreshKind: "refresh_token",
    routes: {
      authorize: "/discord/oauth2/authorize",
      token: "/discord/oauth2/token",
      userinfo: "/discord/api/users/@me",
      revoke: "/discord/oauth2/token/revoke",
    },
    revokeMethods: ["POST"],
    revokeSuccess: { status: 204, body: null },
    refreshIssuedWhen: () => true,
    idTokenIssuedWhen: () => false,
    tokenExpiresIn: 604800,
    tokenBody: (ctx) => ({
      access_token: ctx.access,
      token_type: "Bearer",
      expires_in: 604800,
      refresh_token: ctx.refresh,
      scope: ctx.scopesRaw,
    }),
    userinfoBody: (ctx) => {
      const body = {
        id: SANDBOX_PROFILE.discord.id,
        username: SANDBOX_PROFILE.discord.username,
        discriminator: "0",
        global_name: SANDBOX_PROFILE.discord.globalName,
        avatar: "nshsandboxavatar",
        verified: true,
        flags: 0,
        banner: null,
        accent_color: null,
        premium_type: 0,
        public_flags: 0,
        mfa_enabled: false,
        bot: false,
        system: false,
        locale: "en-US",
      };
      if (ctx.scopes.includes("email")) body.email = SANDBOX_EMAIL;
      return body;
    },
    unauthorized: { status: 401, body: { message: "401: Unauthorized", code: 0 } },
    discoveryDoc: null,
  },

  github: {
    id: "github",
    realm: "nsh-auth sandbox (not GitHub)",
    errorStyle: "github",
    errorStatus: 200, // quirk: token errors come back in-band with HTTP 200
    scopeSeparator: " ",
    defaultScope: "read:user",
    authorizeMode: "query",
    responseModes: ["query"],
    requiresState: false,
    allowCodeIdToken: false,
    tokenMethods: ["POST"],
    formOnly: false,
    contentNegotiation: true, // form-urlencoded by default; Accept: application/json for JSON
    requireRedirectAtToken: false,
    requireClientSecret: false,
    refreshKind: "refresh_token",
    routes: {
      authorize: "/github/login/oauth/authorize",
      token: "/github/login/oauth/access_token",
      userinfo: "/github/api/user",
      revoke: "/github/revoke",
    },
    revokeMethods: ["DELETE", "POST"],
    revokeSuccess: { status: 204, body: null },
    refreshIssuedWhen: ({ scopes }) => scopes.includes("offline_access"),
    idTokenIssuedWhen: () => false,
    tokenExpiresIn: 28800, // only present alongside expiring-user-token refresh tokens
    tokenBody: (ctx) => {
      const body = { access_token: ctx.access, token_type: "bearer", scope: ctx.scopesRaw };
      if (ctx.refresh) {
        body.refresh_token = ctx.refresh;
        body.expires_in = 28800;
        body.refresh_token_expires_in = 15897600;
      }
      return body;
    },
    userinfoBody: (ctx) => ({
      login: SANDBOX_PROFILE.github.login,
      id: SANDBOX_PROFILE.github.id,
      node_id: "MDQ6TlNISFNBTkRCT1g=",
      avatar_url: `${ctx.base}/avatar.png`,
      gravatar_id: "",
      url: `${ctx.base}/github/api/user`,
      html_url: "https://github.invalid/nsh-sandbox-user",
      type: "User",
      site_admin: false,
      name: SANDBOX_PROFILE.github.name,
      company: null,
      blog: "",
      location: null,
      email: SANDBOX_EMAIL,
      bio: "nsh-auth sandbox scripted user",
      public_repos: 0,
      public_gists: 0,
      followers: 0,
      following: 0,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      private_gists: 0,
      total_private_repos: 0,
      owned_private_repos: 0,
      disk_usage: 0,
      collaborators: 0,
      two_factor_authentication: true,
    }),
    unauthorized: {
      status: 401,
      body: { message: "Bad credentials", documentation_url: "https://docs.github.com/rest", status: "401" },
    },
    discoveryDoc: null,
  },

  apple: {
    id: "apple",
    realm: "nsh-auth sandbox (not Apple)",
    errorStyle: "terse",
    errorStatus: 400,
    scopeSeparator: " ",
    defaultScope: "name email",
    authorizeMode: "form_post", // Apple delivers the callback as an auto-submitting form POST
    responseModes: ["form_post", "query"],
    requiresState: true, // Apple requires state on the web flow
    allowCodeIdToken: true,
    tokenMethods: ["POST"],
    formOnly: false,
    contentNegotiation: false,
    requireRedirectAtToken: true,
    requireClientSecret: true, // Apple client_secret is a signed JWT; sandbox accepts any non-empty value
    refreshKind: "refresh_token",
    routes: {
      authorize: "/apple/auth/authorize",
      token: "/apple/auth/token",
      userinfo: null, // Apple has no userinfo endpoint; profile arrives in the callback `user` field
      revoke: "/apple/auth/revoke",
      jwks: "/apple/auth/keys",
    },
    revokeMethods: ["POST"],
    revokeSuccess: { status: 200, body: null },
    refreshIssuedWhen: () => true,
    idTokenIssuedWhen: () => true,
    tokenExpiresIn: 3600,
    tokenBody: (ctx) => ({
      access_token: ctx.access,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: ctx.refresh,
      id_token: ctx.idToken,
    }),
    idTokenClaims: (ctx) => ({
      ...claimsBase("apple", ctx.base, ctx.clientId),
      sub: SANDBOX_PROFILE.apple.sub,
      // Apple encodes these two as strings, unlike everyone else.
      email_verified: "true",
      is_private_email: "false",
      nonce_supported: true,
      auth_time: Math.floor(Date.now() / 1000),
    }),
    discoveryDoc: null,
  },

  microsoft: {
    id: "microsoft",
    realm: "nsh-auth sandbox (not Microsoft)",
    errorStyle: "aadsts",
    errorStatus: 400,
    scopeSeparator: " ",
    defaultScope: "openid profile email offline_access",
    authorizeMode: "query",
    responseModes: ["query", "fragment", "form_post"],
    requiresState: false,
    allowCodeIdToken: false,
    tokenMethods: ["POST"],
    formOnly: false,
    contentNegotiation: false,
    requireRedirectAtToken: true,
    requireClientSecret: false,
    refreshKind: "refresh_token",
    tenantRoute: true,
    routes: {
      authorize: "/microsoft/{tenant}/oauth2/v2.0/authorize",
      token: "/microsoft/{tenant}/oauth2/v2.0/token",
      userinfo: "/microsoft/common/oidc/userinfo",
      jwks: "/microsoft/common/discovery/v2.0/keys",
      jwksAlias: "/microsoft/discovery/v2.0/keys",
      discovery: "/microsoft/{tenant}/v2.0/.well-known/openid-configuration",
    },
    revokeMethods: [],
    refreshIssuedWhen: ({ scopes }) => scopes.includes("offline_access"),
    idTokenIssuedWhen: ({ scopes }) => scopes.includes("openid"),
    tokenExpiresIn: 3599,
    tokenBody: (ctx) => {
      const body = {
        token_type: "Bearer",
        scope: ctx.scopesRaw,
        expires_in: 3599,
        ext_expires_in: 3599,
        access_token: ctx.access,
      };
      if (ctx.refresh) body.refresh_token = ctx.refresh;
      if (ctx.idToken) body.id_token = ctx.idToken;
      return body;
    },
    idTokenClaims: (ctx) => ({
      ...claimsBase("microsoft", ctx.base, ctx.clientId),
      iss: `${ctx.base}/microsoft/${ctx.tenant ?? "common"}`,
      sub: SANDBOX_PROFILE.microsoft.sub,
      oid: SANDBOX_PROFILE.microsoft.sub,
      tid: ctx.tenant ?? "common",
      name: SANDBOX_PROFILE.microsoft.name,
      preferred_username: SANDBOX_EMAIL,
      ver: "1.0",
    }),
    userinfoBody: (ctx) => ({
      sub: SANDBOX_PROFILE.microsoft.sub,
      name: SANDBOX_PROFILE.microsoft.name,
      family_name: "User",
      given_name: "Sandbox",
      picture: `${ctx.base}/avatar.png`,
      email: SANDBOX_EMAIL,
    }),
    unauthorized: {
      status: 401,
      headers: { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="nsh-auth sandbox (not Microsoft): access token is invalid (sandbox_reason: invalid_token)"' },
      body: null, // real Graph replies 401 with an empty body and the WWW-Authenticate header
    },
    discoveryDoc: (base, r, tenant) => ({
      issuer: `${base}/microsoft/${tenant ?? "common"}`,
      authorization_endpoint: base + r.authorize.replace("{tenant}", tenant ?? "common"),
      token_endpoint: base + r.token.replace("{tenant}", tenant ?? "common"),
      userinfo_endpoint: base + r.userinfo,
      jwks_uri: base + r.jwks,
      scopes_supported: ["openid", "profile", "email", "offline_access"],
      response_modes_supported: ["query", "fragment", "form_post"],
      response_types_supported: ["code", "id_token", "code id_token"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["pairwise"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    }),
  },

  x: {
    id: "x",
    realm: "nsh-auth sandbox (not X)",
    errorStyle: "flat",
    errorStatus: 400,
    scopeSeparator: " ",
    defaultScope: "tweet.read users.read offline.access",
    authorizeMode: "query",
    responseModes: ["query"],
    requiresState: true, // X requires state, up to 500 chars
    allowCodeIdToken: false,
    tokenMethods: ["POST"],
    formOnly: false,
    contentNegotiation: false,
    requireRedirectAtToken: true,
    requireClientSecret: false,
    refreshNeedsClientId: true, // public clients must repeat client_id on refresh
    refreshKind: "refresh_token",
    routes: {
      authorize: "/x/i/oauth2/authorize",
      token: "/x/2/oauth2/token",
      userinfo: "/x/2/users/me",
      revoke: "/x/2/oauth2/revoke",
    },
    revokeMethods: ["POST"],
    revokeSuccess: { status: 200, body: {} },
    refreshIssuedWhen: ({ scopes }) => scopes.includes("offline.access"),
    idTokenIssuedWhen: () => false,
    tokenExpiresIn: 7200,
    tokenBody: (ctx) => {
      const body = { token_type: "bearer", expires_in: 7200, access_token: ctx.access, scope: ctx.scopesRaw };
      if (ctx.refresh) body.refresh_token = ctx.refresh;
      return body;
    },
    userinfoBody: () => ({
      data: {
        id: SANDBOX_PROFILE.x.id,
        name: SANDBOX_PROFILE.x.name,
        username: SANDBOX_PROFILE.x.username,
        created_at: "2026-01-01T00:00:00.000Z",
        description: "nsh-auth sandbox scripted user",
        location: "sandbox",
        verified: false,
        protected: false,
        public_metrics: { followers_count: 0, following_count: 0, tweet_count: 0, listed_count: 0 },
        url: null,
      },
    }),
    unauthorized: {
      status: 401,
      body: { title: "Unauthorized", type: "about:blank", status: 401, detail: "Unauthorized (nsh-auth sandbox, not X)" },
    },
    discoveryDoc: null,
  },

  oidc: {
    id: "oidc",
    realm: "nsh-auth sandbox generic OIDC provider",
    errorStyle: "flat",
    errorStatus: 400,
    scopeSeparator: " ",
    defaultScope: "openid email profile offline_access",
    authorizeMode: "query",
    responseModes: ["query"],
    requiresState: false,
    allowCodeIdToken: false,
    tokenMethods: ["POST"],
    formOnly: false,
    contentNegotiation: false,
    requireRedirectAtToken: true,
    requireClientSecret: false,
    refreshKind: "refresh_token",
    routes: {
      authorize: "/oidc/authorize",
      token: "/oidc/token",
      userinfo: "/oidc/userinfo",
      revoke: "/oidc/revoke",
      jwks: "/oidc/.well-known/jwks.json",
      discovery: "/oidc/.well-known/openid-configuration",
    },
    revokeMethods: ["POST", "GET"],
    revokeSuccess: { status: 200, body: null },
    refreshIssuedWhen: () => true,
    idTokenIssuedWhen: ({ scopes }) => scopes.includes("openid"),
    tokenExpiresIn: 3600,
    tokenBody: (ctx) => {
      const body = {
        access_token: ctx.access,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: ctx.refresh,
        scope: ctx.scopesRaw,
      };
      if (ctx.idToken) body.id_token = ctx.idToken;
      return body;
    },
    idTokenClaims: (ctx) => ({
      ...claimsBase("oidc", ctx.base, ctx.clientId),
      sub: SANDBOX_PROFILE.oidc.sub,
      name: SANDBOX_PROFILE.oidc.name,
      given_name: SANDBOX_PROFILE.oidc.given_name,
      family_name: SANDBOX_PROFILE.oidc.family_name,
      picture: `${ctx.base}/avatar.png`,
      email_verified: true,
    }),
    userinfoBody: (ctx) => ({
      sub: SANDBOX_PROFILE.oidc.sub,
      name: SANDBOX_PROFILE.oidc.name,
      given_name: SANDBOX_PROFILE.oidc.given_name,
      family_name: SANDBOX_PROFILE.oidc.family_name,
      picture: `${ctx.base}/avatar.png`,
      email: SANDBOX_EMAIL,
      email_verified: true,
    }),
    unauthorized: { status: 401, headers: { "WWW-Authenticate": 'Bearer error="invalid_token"' }, body: { error: "invalid_token", error_description: "The access token is invalid or expired. (sandbox_reason: invalid_token)" } },
    discoveryDoc: (base, r) => ({
      issuer: `${base}/oidc`,
      authorization_endpoint: base + r.authorize,
      token_endpoint: base + r.token,
      userinfo_endpoint: base + r.userinfo,
      revocation_endpoint: base + r.revoke,
      jwks_uri: base + r.jwks,
      scopes_supported: ["openid", "email", "profile", "offline_access"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256", "plain"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    }),
  },

  mock: {
    id: "mock",
    realm: "nsh-auth sandbox plain mock provider",
    errorStyle: "flat",
    errorStatus: 400,
    scopeSeparator: " ",
    defaultScope: "openid email profile offline_access",
    authorizeMode: "query",
    responseModes: ["query"],
    requiresState: false,
    allowCodeIdToken: false,
    tokenMethods: ["POST"],
    formOnly: false,
    contentNegotiation: false,
    requireRedirectAtToken: true,
    requireClientSecret: false,
    refreshKind: "refresh_token",
    routes: {
      authorize: "/mock/authorize",
      token: "/mock/token",
      userinfo: "/mock/userinfo",
      revoke: "/mock/revoke",
      jwks: "/mock/.well-known/jwks.json",
      discovery: "/mock/.well-known/openid-configuration",
    },
    revokeMethods: ["POST", "GET"],
    revokeSuccess: { status: 200, body: null },
    refreshIssuedWhen: () => true,
    idTokenIssuedWhen: () => true, // convenience: the plain mock provider always issues an id_token
    tokenExpiresIn: 3600,
    tokenBody: (ctx) => {
      const body = {
        access_token: ctx.access,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: ctx.refresh,
        scope: ctx.scopesRaw,
      };
      if (ctx.idToken) body.id_token = ctx.idToken;
      return body;
    },
    idTokenClaims: (ctx) => ({
      ...claimsBase("mock", ctx.base, ctx.clientId),
      sub: SANDBOX_PROFILE.mock.sub,
      name: SANDBOX_PROFILE.mock.name,
      given_name: SANDBOX_PROFILE.mock.given_name,
      family_name: SANDBOX_PROFILE.mock.family_name,
      picture: `${ctx.base}/avatar.png`,
      email_verified: true,
    }),
    userinfoBody: (ctx) => ({
      sub: SANDBOX_PROFILE.mock.sub,
      name: SANDBOX_PROFILE.mock.name,
      given_name: SANDBOX_PROFILE.mock.given_name,
      family_name: SANDBOX_PROFILE.mock.family_name,
      picture: `${ctx.base}/avatar.png`,
      email: SANDBOX_EMAIL,
      email_verified: true,
    }),
    unauthorized: { status: 401, headers: { "WWW-Authenticate": 'Bearer error="invalid_token"' }, body: { error: "invalid_token", error_description: "The access token is invalid or expired. (sandbox_reason: invalid_token)" } },
    discoveryDoc: (base, r) => ({
      issuer: `${base}/mock`,
      authorization_endpoint: base + r.authorize,
      token_endpoint: base + r.token,
      userinfo_endpoint: base + r.userinfo,
      revocation_endpoint: base + r.revoke,
      jwks_uri: base + r.jwks,
      scopes_supported: ["openid", "email", "profile", "offline_access"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256", "plain"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    }),
  },
};

// Apple's web callback carries the scripted user's profile in the `user` field,
// first grant only in reality; the sandbox always includes it.
export const APPLE_USER_FIELD = JSON.stringify({
  name: { firstName: SANDBOX_PROFILE.apple.firstName, lastName: SANDBOX_PROFILE.apple.lastName },
  email: SANDBOX_EMAIL,
});
