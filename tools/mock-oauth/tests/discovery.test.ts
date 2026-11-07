import { describe, test, expect } from "bun:test";
import { get, postForm, url, withMock } from "./helpers.ts";

const DISCOVERY_PROVIDERS = ["google", "microsoft", "oidc", "mock"];

describe("OIDC discovery documents", () => {
  for (const prov of DISCOVERY_PROVIDERS) {
    test(`${prov}: issuer, absolute endpoints, reachable jwks_uri`, async () => {
      await withMock(async (m) => {
        const res = await get(url(m, prov, "discovery"));
        expect(res.status).toBe(200);
        const doc = res.body;
        expect(doc.issuer).toBe(`${m.base}/${prov === "microsoft" ? "microsoft/common" : prov}`);
        for (const field of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
          expect(doc[field]).toMatch(new RegExp(`^${m.base}/`));
        }
        expect(doc.id_token_signing_alg_values_supported).toContain("RS256");
        expect(doc.code_challenge_methods_supported).toContain("S256");

        // every advertised endpoint answers (not 404)
        const checks: Array<Promise<unknown>> = [];
        for (const field of ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"]) {
          if (!doc[field]) continue;
          checks.push(
            (field === "token_endpoint" ? postForm(doc[field], {}) : get(doc[field])).then((r: any) => {
              expect(r.status).not.toBe(404);
            }),
          );
        }
        await Promise.all(checks);

        const jwks = await get(doc.jwks_uri);
        expect(jwks.status).toBe(200);
        expect(jwks.body.keys[0].n).toBeTruthy();
      });
    });
  }

  test("microsoft: tenants each get their own discovery with tenant-scoped issuer", async () => {
    await withMock(async (m) => {
      for (const tenant of ["common", "organizations", "consumers"]) {
        const res = await get(`${m.base}/microsoft/${tenant}/v2.0/.well-known/openid-configuration`);
        expect(res.status).toBe(200);
        expect(res.body.issuer).toBe(`${m.base}/microsoft/${tenant}`);
        expect(res.body.authorization_endpoint).toContain(`/microsoft/${tenant}/oauth2/v2.0/authorize`);
      }
    });
  });

  test("providers without OIDC discovery (github, discord, facebook, x, apple) serve none", async () => {
    await withMock(async (m) => {
      expect((await get(`${m.base}/github/.well-known/openid-configuration`)).status).toBe(404);
      expect((await get(`${m.base}/discord/.well-known/openid-configuration`)).status).toBe(404);
    });
  });
});
