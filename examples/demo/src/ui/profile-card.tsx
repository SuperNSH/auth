// The user profile, loaded from the mock's userinfo endpoint through nsh-query
// (TanStack Query on NSH). Call createProfileQuery inside a component;
// ProfileView draws the result.
import { Text, View } from "nsh";
import { type QueryObserverResult, createQuery, QueryClient } from "nsh-query";

export interface Profile {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
}

const TTL_MS = 30_000;

// One client for every profile query, passed explicitly — no provider subtree
// to mount. Retry off: a stale-token userinfo does not heal by retrying; the
// refresh button is the recovery path.
const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

export function createProfileQuery(props: {
  baseUrl: string;
  /** The realm segment (mock, oidc, ...); the query key follows it, so a
   * provider switch cannot serve the previous realm's cached profile. */
  provider: () => string | undefined;
  token: () => string | undefined;
}): QueryObserverResult<Profile, Error> {
  // The accessor form keeps the key, the token gate and the realm in step with
  // the session: changing any of them moves the query instead of serving a
  // stale cache entry.
  return createQuery<Profile>(() => ({
    queryKey: ["userinfo", props.provider() ?? "none"],
    queryFn: async ({ signal }) => {
      const response = await fetch(`${props.baseUrl}/${props.provider()}/userinfo`, {
        headers: { Authorization: `Bearer ${props.token()}` },
        signal,
      });
      if (!response.ok) throw new Error(`userinfo failed: HTTP ${response.status}`);
      return (await response.json()) as Profile;
    },
    enabled: props.token() !== undefined,
    staleTime: TTL_MS,
  }), client);
}

export function ProfileView(props: { query: QueryObserverResult<Profile, Error> }) {
  // The result is a reactiveResult: its fields are getters, read as plain
  // properties; only refetch is a method.
  const query = props.query;
  return (
    <View class="gap-2 rounded-(--radius) border border-border bg-card p-4" testID="profile-card">
      <Text class="text-sm font-medium text-card-foreground">Profile</Text>
      <If when={query.isPending}>
        <Text class="text-sm text-muted-foreground">Loading profile…</Text>
      </If>
      <If when={query.error}>
        {(error) => <Text class="text-sm text-destructive">Profile failed: {String(error())}</Text>}
      </If>
      <If when={query.data}>
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
