// The user profile, loaded from the mock's userinfo endpoint through nsh-query.
// Call createProfileQuery inside a component; ProfileView draws the result.
import { Text, View } from "nsh";
import { createQuery, noRetries, type Query } from "nsh-query";

export interface Profile {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
}

const TTL_MS = 30_000;

export function createProfileQuery(props: {
  baseUrl: string;
  /** The realm segment (mock, oidc, ...); the query key follows it, so a
   * provider switch cannot serve the previous realm's cached profile. */
  provider: () => string | undefined;
  token: () => string | undefined;
}): Query<Profile> {
  return createQuery<Profile>({
    key: () => ["userinfo", props.provider() ?? "none"],
    cache: { ttlMs: TTL_MS },
    // A failed userinfo (a stale token) does not heal by retrying; the
    // refresh button is the recovery path.
    retry: noRetries,
    // No session, no userinfo call: the enabled getter follows the token.
    enabled: () => props.token() !== undefined,
    fetch: async ({ signal }) => {
      const response = await fetch(`${props.baseUrl}/${props.provider()}/userinfo`, {
        headers: { Authorization: `Bearer ${props.token()}` },
        signal,
      });
      if (!response.ok) throw new Error(`userinfo failed: HTTP ${response.status}`);
      return (await response.json()) as Profile;
    },
  });
}

export function ProfileView(props: { query: Query<Profile> }) {
  const profile = () => props.query;
  return (
    <View class="gap-2 rounded-(--radius) border border-border bg-card p-4" testID="profile-card">
      <Text class="text-sm font-medium text-card-foreground">Profile</Text>
      <If when={profile().isPending()}>
        <Text class="text-sm text-muted-foreground">Loading profile…</Text>
      </If>
      <If when={profile().error()}>
        {(error) => <Text class="text-sm text-destructive">Profile failed: {String(error())}</Text>}
      </If>
      <If when={profile().data()}>
        {(data) => (
          <View class="gap-1">
            <Text class="text-base font-semibold text-card-foreground">{data().name ?? data().sub}</Text>
            <If when={data().email}>
              {(email) => <Text class="text-sm text-muted-foreground">{email()}</Text>}
            </If>
            <Text class="text-sm text-muted-foreground">{data().sub}</Text>
          </View>
        )}
      </If>
    </View>
  );
}
