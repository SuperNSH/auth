// The root: auth init (the config must be final before createAuth runs), then
// one screen per auth state. Page logic lives in the screens; the package's
// signals drive the switch.
import { cleanup, effect, host, Text, View } from "nsh";
import { authBusy, authConfig, authReady, handleRedirect, initAuth, refreshSession, session, signIn, signOut } from "./auth";
import { AccountScreen } from "./screens/account-screen";
import { SignInScreen } from "./screens/sign-in-screen";

export function App() {
  // Runs once: reads the host's config (async), then builds the auth instance.
  effect(() => {
    void initAuth();
  });
  return (
    <If
      when={authReady()}
      else={
        <View class="flex-1 items-center justify-center bg-background">
          <Text class="text-sm text-muted-foreground">Loading…</Text>
        </View>
      }
    >
      {() => <AuthRoot />}
    </If>
  );
}

function AuthRoot() {
  // The web host's event is the return leg there (a page bridge forwards the
  // redirect); the iOS and Android hosts return the callback from auth.authorize
  // itself, so this listener stays quiet on them. Rendering-time registration
  // stops with AuthRoot.
  const stopRedirect = host.on("auth.redirect", (payload) => {
    const url = (payload as { url?: unknown } | null)?.url;
    if (typeof url === "string") void handleRedirect(url).catch(() => {});
  });
  cleanup(stopRedirect);

  // Test-only hook (no real host sends it): fires concurrent refreshes at once,
  // so a headless test can watch the package's single-flight through the UI.
  const stopRefreshBurst = host.on("auth.test.refreshBurst", (payload) => {
    const count = (payload as { count?: unknown } | null)?.count;
    if (typeof count === "number" && count > 0) {
      void Promise.all(Array.from({ length: count }, () => refreshSession().catch(() => {})));
    }
  });
  cleanup(stopRefreshBurst);

  // Launch arguments only: a standalone build never has autoStart (see README).
  effect(() => {
    const start = authConfig().autoStart;
    if (start) void signIn(start).catch(() => {});
  });

  return (
    <View class="flex-1 bg-background">
      <If when={session()} else={<SignInScreen busy={authBusy()} onStart={(provider) => void signIn(provider).catch(() => {})} />}>
        {() => <AccountScreen onSignOut={() => void signOut().catch(() => {})} />}
      </If>
    </View>
  );
}
