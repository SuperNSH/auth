// UI preview: the demo's styled pieces with fake data and no nsh-auth import, so
// the look, the form and the userinfo query stay testable independently of the
// sibling package. Not part of the real app flow.
import { mount, signal, Scroll, Text, View } from "nsh";
import { AccountActions } from "./src/components/account-actions";
import { CallbackPasteBack } from "./src/components/callback-paste-back";
import { EmailForm } from "./src/components/email-form";
import { ProviderButton } from "./src/components/provider-button";
import { PROVIDERS, type ProviderId } from "./src/providers";
import { Button } from "./src/ui/button";
import { ClaimsTable } from "./src/ui/claims-table";
import { ErrorBanner } from "./src/ui/error-banner";
import { ProfileView, createProfileQuery } from "./src/ui/profile-card";
import { MOCK_BASE_URL, PREVIEW_CLAIMS } from "./src/dev/fixtures";

// Realm-switch probe: the profile query's key follows the provider, so this
// must load the other realm's profile instead of serving the cached one.
function RealmSwitchProbe() {
  const realm = signal<"mock" | "oidc">("mock");
  const profile = createProfileQuery({
    baseUrl: MOCK_BASE_URL,
    provider: () => realm(),
    token: () => "preview-token",
  });
  return (
    <View class="gap-2" testID="realm-switch">
      <Button
        label={`Switch realm (now: ${realm()})`}
        variant="outline"
        onPress={() => realm.update((current) => (current === "mock" ? "oidc" : "mock"))}
        testID="switch-realm"
      />
      <ProfileView query={profile} />
    </View>
  );
}

function PreviewApp() {
  const pressed = signal<ProviderId | null>(null);
  const profile = createProfileQuery({
    baseUrl: MOCK_BASE_URL,
    provider: () => "mock",
    token: () => "preview-token",
  });
  return (
    <View class="flex-1 bg-background">
      <View class="gap-2 border-b border-border p-4 pt-[calc(env(safe-area-inset-top)+16px)]">
        <Text class="text-xl font-semibold text-foreground">UI preview</Text>
        <Text class="text-sm text-muted-foreground">Fake data; exercises no sign-in flow.</Text>
      </View>
      <Scroll testID="content-scroll" class="flex-1" contentClass="gap-4 p-4 pb-[calc(env(safe-area-inset-bottom)+24px)]">
        <ErrorBanner code="access_denied" message="The mock user denied the request." />
        <EmailForm />
        <View class="gap-2">
          <Each of={PROVIDERS} key={(provider) => provider.id}>
            {(provider) => (
              <ProviderButton provider={provider().id} onPress={() => pressed.set(provider().id)} />
            )}
          </Each>
        </View>
        <If when={pressed()}>
          {(id) => <Text class="text-sm text-muted-foreground">{`Pressed: ${id()}`}</Text>}
        </If>
        {/* The account screen's signed-in-state controls; handlers are no-ops here. */}
        <View class="gap-2" testID="account-actions-preview">
          <Text class="text-sm font-medium text-card-foreground">Account actions (signed-in state)</Text>
          <AccountActions onRefresh={() => {}} onSignOut={() => {}} />
        </View>
        <ClaimsTable claims={PREVIEW_CLAIMS} accessTokenTail="d tok" refreshTokenPresent />
        <CallbackPasteBack />
        <ProfileView query={profile} />
        <RealmSwitchProbe />
      </Scroll>
    </View>
  );
}

mount(PreviewApp);
