// The app root factory. The native entry (App.tsx) mounts the nsh-query-backed
// account screen; the web entry (App.web.tsx) mounts its web variant —
// nsh-query's lifecycle import crashes the 0.4.0 web runtime, so the two
// entries are the per-surface switch and there is no runtime platform check.
import { cleanup, effect, host, Text, View } from "nsh";
import type { JSX } from "nsh";
import {
  authBusy,
  authConfig,
  authReady,
  handleRedirect,
  initAuth,
  refreshSession,
  session,
  signIn,
  signOut,
} from "./auth";
import { SignInScreen } from "./screens/sign-in-screen";

type AccountScreenComponent = (props: { onSignOut: () => void }) => JSX.Element;

/** Builds the root around an account screen variant; App.tsx and App.web.tsx call this. */
export function createAppRoot(AccountScreen: AccountScreenComponent) {
  return function AppRoot() {
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
        {() => <AuthRoot AccountScreen={AccountScreen} />}
      </If>
    );
  };
}

function AuthRoot(props: { AccountScreen: AccountScreenComponent }) {
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

  const Screen = props.AccountScreen;
  return (
    <View class="flex-1 bg-background">
      <If when={session()} else={<SignInScreen busy={authBusy()} onStart={(provider) => void signIn(provider).catch(() => {})} />}>
        {() => <Screen onSignOut={() => void signOut().catch(() => {})} />}
      </If>
    </View>
  );
}
