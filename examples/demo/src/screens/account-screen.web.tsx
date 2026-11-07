// The session screen for the web entry: identical except the profile card —
// nsh-query's lifecycle import is missing on the 0.4.0 web runtime (it crashes
// the whole app), so web shows the note and relies on ID-token claims.
import { Text, View } from "nsh";
import { claimInfo, refreshSession, status, user } from "../auth";
import { contact } from "../store";
import { AuthErrorBanner } from "../components/auth-error-banner";
import { AccountActions } from "../components/account-actions";
import { ClaimsTable } from "../ui/claims-table";

export function AccountScreenWeb(props: { onSignOut: () => void }) {
  const claims = () => claimInfo();
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
        <View class="gap-2 rounded-(--radius) border border-border bg-card p-4" testID="profile-web-note">
          <Text class="text-sm font-medium text-card-foreground">Profile</Text>
          <Text class="text-sm text-muted-foreground">
            Profile loading is native-only for now: nsh-query's lifecycle dependency is missing on
            the web runtime in nsh 0.4.0 (upstream). Your identity below comes from the ID token's
            claims; refresh and sign-out still work.
          </Text>
        </View>
        <If when={contact()}>
          {(saved) => <Text class="text-sm text-muted-foreground">{`Contact: ${saved()}`}</Text>}
        </If>
        <ClaimsTable
          claims={claims().claims}
          accessTokenTail={claims().accessTokenTail}
          refreshTokenPresent={claims().refreshTokenPresent}
        />
        <AccountActions onRefresh={() => void refreshSession().catch(() => {})} onSignOut={props.onSignOut} />
      </View>
    </View>
  );
}
