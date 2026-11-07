// The session screen (native entry): status line, package user, userinfo
// profile through nsh-query, the tokens readout, and refresh/sign-out.
// The web entry mounts account-screen.web instead: nsh-query's lifecycle
// import is missing on the 0.4.0 web runtime and crashes it.
import { Text, View } from "nsh";
import { authConfig, claimInfo, refreshSession, session, status, user } from "../auth";
import { contact } from "../store";
import { AuthErrorBanner } from "../components/auth-error-banner";
import { AccountActions } from "../components/account-actions";
import { ClaimsTable } from "../ui/claims-table";
import { ProfileView, createProfileQuery } from "../ui/profile-card";

export function AccountScreen(props: { onSignOut: () => void }) {
  const config = authConfig();
  const profile = createProfileQuery({
    baseUrl: config.mockBaseUrl,
    // One mock realm per provider (tools/mock-oauth route table, mirrored by
    // the package's provider config): mock -> /mock, oidc -> /oidc. A session
    // from a real provider has no realm here, and its profile read fails —
    // honestly shown by the card's error state.
    provider: () => session()?.provider,
    token: () => session()?.accessToken ?? undefined,
  });
  // A closure, not a body snapshot: refresh swaps the session and the readout follows.
  const claims = () => claimInfo();
  const refresh = () => {
    profile.refetch();
    void refreshSession().catch(() => {});
  };
  return (
    <View class="flex-1 bg-background">
      <View class="gap-2 border-b border-border p-4">
        <Text class="text-xl font-semibold text-foreground">Account</Text>
        <Text class="text-sm text-muted-foreground">{`Status: ${status()}`}</Text>
        <If when={user()}>
          {(who) => (
            <Text class="text-sm text-muted-foreground">
              {`Signed in as ${who().name ?? who().id ?? "unknown user"}`}
            </Text>
          )}
        </If>
      </View>
      <View class="flex-1 gap-4 p-4 pb-6">
        <AuthErrorBanner />
        <ProfileView query={profile} />
        <If when={contact()}>
          {(saved) => <Text class="text-sm text-muted-foreground">{`Contact: ${saved()}`}</Text>}
        </If>
        <ClaimsTable
          claims={claims().claims}
          accessTokenTail={claims().accessTokenTail}
          refreshTokenPresent={claims().refreshTokenPresent}
        />
        <AccountActions onRefresh={refresh} onSignOut={props.onSignOut} />
      </View>
    </View>
  );
}
