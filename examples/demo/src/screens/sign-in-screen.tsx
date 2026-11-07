// The sign-in screen: the contact email form, then one button per provider.
// Fixed padding on every surface: the env() safe-area handle crashes the
// 0.4.0 web runtime, and there is no safe platform detection to gate it.
import { Scroll, Text, View, host } from "nsh";
import { PROVIDERS, type ProviderId } from "../providers";
import { AuthErrorBanner } from "../components/auth-error-banner";
import { CallbackPasteBack } from "../components/callback-paste-back";
import { EmailForm } from "../components/email-form";
import { ProviderButton } from "../components/provider-button";

export function SignInScreen(props: { busy: boolean; onStart: (provider: ProviderId) => void }) {
  return (
    <View class="flex-1 bg-background">
      <ScreenHeader />
      <Scroll class="flex-1" contentClass="gap-4 p-4 pb-6">
        <AuthErrorBanner />
        <If when={props.busy}>
          <Text class="text-sm text-muted-foreground" testID="auth-waiting">
            Waiting for the provider's redirect…
          </Text>
        </If>
        <EmailForm />
        <View class="gap-2">
          <Each of={PROVIDERS} key={(provider) => provider.id}>
            {(provider) => (
              <ProviderButton
                provider={provider().id}
                disabled={props.busy}
                onPress={() => props.onStart(provider().id)}
              />
            )}
          </Each>
        </View>
        <If when={!host.available()}>
          <CallbackPasteBack />
        </If>
      </Scroll>
    </View>
  );
}

function ScreenHeader() {
  return (
    <View class="gap-2 border-b border-border p-4">
      <Text class="text-xl font-semibold text-foreground">Sign in</Text>
      <Text class="text-sm text-muted-foreground">
        Sandbox demo: fake client ids, local mock only. No real provider is signed in to.
      </Text>
      <If when={!host.available()}>
        <Text class="text-sm text-muted-foreground">
          No embedding host: sign-in opens the system browser, then waits — a standalone build has no
          way to catch the redirect. Finish with the paste-in box below, or run inside examples/host-ios,
          host-android or the web host for the full loop.
        </Text>
      </If>
    </View>
  );
}
