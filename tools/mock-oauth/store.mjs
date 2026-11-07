import { randomBytes } from "node:crypto";

const CODE_TTL_MS = 120_000; // brief: codes expire after 120 seconds (expired_code)

export function createStore() {
  const codes = new Map(); // code -> entry
  const refresh = new Map(); // refresh token -> { family, used, revoked, provider }
  const access = new Map(); // access token -> { family, provider, scopes, issuedAt }
  const families = new Map(); // family id -> { revoked, provider, clientId, scopes, scopesRaw, nonce }

  const now = () => Date.now();

  function trim(map, max) {
    while (map.size > max) map.delete(map.keys().next().value);
  }

  return {
    CODE_TTL_MS,

    putCode(entry) {
      const code = "nsh-sandbox-code-" + randomBytes(18).toString("base64url");
      codes.set(code, { ...entry, code, used: false, createdAt: now(), expiresAt: now() + CODE_TTL_MS });
      trim(codes, 500);
      return code;
    },

    getCode(code) {
      const entry = codes.get(code);
      if (!entry) return null;
      entry.expired = entry.expiresAt <= now();
      return entry;
    },

    markCodeUsed(code) {
      const entry = codes.get(code);
      if (entry) entry.used = true;
    },

    newFamily({ provider, clientId, scopes, scopesRaw, nonce }) {
      const id = randomBytes(12).toString("base64url");
      const family = { id, revoked: false, provider, clientId, scopes, scopesRaw, nonce };
      families.set(id, family);
      return family;
    },

    getFamily(id) {
      return families.get(id) ?? null;
    },

    issueAccessToken(family) {
      const token = accessTokenString(family.provider);
      access.set(token, { family: family.id, provider: family.provider, scopes: family.scopes, issuedAt: now() });
      trim(access, 4000);
      return token;
    },

    issueRefreshToken(family) {
      const token = refreshTokenString(family.provider);
      refresh.set(token, { family: family.id, used: false, revoked: false, provider: family.provider });
      trim(refresh, 4000);
      return token;
    },

    getRefresh(token) {
      return refresh.get(token) ?? null;
    },

    getAccess(token) {
      const rec = access.get(token);
      if (!rec) return null;
      const family = families.get(rec.family);
      rec.familyRevoked = family?.revoked ?? false;
      return rec;
    },

    // Single-use refresh: rotation marks the old token used; reuse revokes the family.
    rotateRefresh(refRec) {
      refRec.used = true;
      const family = families.get(refRec.family);
      const newRefresh = this.issueRefreshToken(family);
      const newAccess = this.issueAccessToken(family);
      return { accessToken: newAccess, refreshToken: newRefresh, family };
    },

    revokeFamily(familyId) {
      const family = families.get(familyId);
      if (family) family.revoked = true;
      for (const rec of refresh.values()) if (rec.family === familyId) rec.revoked = true;
    },

    revokeToken(token) {
      const r = refresh.get(token);
      if (r) { this.revokeFamily(r.family); return true; }
      const a = access.get(token);
      if (a) { this.revokeFamily(a.family); return true; }
      return false;
    },

    expireAllCodes() {
      for (const entry of codes.values()) entry.expiresAt = now() - 1;
    },

    reset() {
      codes.clear(); refresh.clear(); access.clear(); families.clear();
    },

    stats() {
      let liveFamilies = 0;
      for (const f of families.values()) if (!f.revoked) liveFamilies++;
      return { codes: codes.size, refreshTokens: refresh.size, accessTokens: access.size, families: liveFamilies };
    },
  };
}

// Token formats keep each provider's real prefix style while staying unmistakably sandbox.
function accessTokenString(provider) {
  switch (provider) {
    case "github": return "gho_nshsandbox" + randomBytes(16).toString("hex");
    case "facebook": return "EAAGnshsandbox" + randomBytes(24).toString("base64url");
    case "microsoft": return "nsh-sandbox-msat-" + randomBytes(24).toString("base64url");
    default: return `nsh-sandbox-${provider}-at-` + randomBytes(18).toString("base64url");
  }
}

function refreshTokenString(provider) {
  switch (provider) {
    case "github": return "ghr_nshsandbox" + randomBytes(16).toString("hex");
    case "microsoft": return "nsh-sandbox-msrt-" + randomBytes(24).toString("base64url");
    default: return `nsh-sandbox-${provider}-rt-` + randomBytes(18).toString("base64url");
  }
}
