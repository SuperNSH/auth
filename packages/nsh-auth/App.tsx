// Test harness for the nsh-auth core: every gate runs through these controls.
// The styled demo UI lives in examples/demo; this surface stays plain on purpose.
import { host, mount, signal, Text, View } from "nsh";
import { Input } from "nsh/base";
import { createAuth, type ProviderId } from "./src";

const PROVIDERS: ProviderId[] = ["google", "facebook", "discord", "github", "apple", "microsoft", "x", "oidc", "mock"];

const brokerParam = host.params.brokerUrl;

function audienceOf(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

const audiencesParam = host.params.nativeAudiences;
const nativeAudiences =
  audiencesParam && typeof audiencesParam === "object" && !Array.isArray(audiencesParam)
    ? {
        google: audienceOf((audiencesParam as Record<string, unknown>).google),
        apple: audienceOf((audiencesParam as Record<string, unknown>).apple),
      }
    : undefined;

const authorizeUrlDraft = signal("");

const auth = createAuth({
  clientId: "nsh-auth-sandbox.apps.googleusercontent.com",
  redirectUri: "nsh.auth.sandbox://callback",
  brokerUrl: typeof brokerParam === "string" ? brokerParam : undefined,
  nativeAudiences,
  clock: { nowMs: () => Date.now() },
  onAuthorizeUrl: (url) => authorizeUrlDraft.set(url),
});

const callbackDraft = signal("");

// Test hook: host.params.autoSignIn (providers, in order) starts unattended
// sign-ins, autoSignInGapMs apart on the app's clock, so tests can race flows.
const autoSignIn = host.params.autoSignIn;
const autoSignInGap = host.params.autoSignInGapMs;
if (Array.isArray(autoSignIn)) {
  const gap = typeof autoSignInGap === "number" ? autoSignInGap : 0;
  autoSignIn.forEach((provider, index) => {
    if (typeof provider !== "string") return;
    setTimeout(() => auth.signIn(provider as ProviderId).catch(() => {}), index * gap);
  });
}

async function submitCallback(): Promise<void> {
  try {
    await auth.handleRedirect(callbackDraft());
  } catch {
    // the error signal shows it
  }
  callbackDraft.set("");
}

async function refreshEight(): Promise<void> {
  try {
    await Promise.all(Array.from({ length: 8 }, () => auth.refresh()));
  } catch {
    // the error signal shows it
  }
}

function App() {
  return (
    <View class="flex-1 gap-2 bg-background p-4">
      <Text testID="status" class="text-foreground">{`status ${auth.status()}`}</Text>
      <If when={auth.status() === "authorizing" ? authorizeUrlDraft() : ""}>
        {(url) => (
          <Text testID="authorize-url" class="text-muted-foreground">
            {url()}
          </Text>
        )}
      </If>
      <If when={auth.status() !== "idle" && auth.status() !== "error"}>
        <Text
          testID="sign-out-anytime"
          role="button"
          accessibilityLabel="Sign out now"
          onPress={() => auth.signOut().catch(() => {})}
          class="text-primary"
        >
          Sign out now
        </Text>
      </If>
      <If when={auth.error()}>
        {(failure) => (
          <Text testID="error" role="alert" class="text-destructive">
            {`error ${failure().code}`}
          </Text>
        )}
      </If>
      <If
        when={auth.session()}
        else={
          <View class="gap-2">
            <Each of={PROVIDERS}>
              {(provider) => (
                <Text
                  testID={`sign-in-${provider()}`}
                  role="button"
                  accessibilityLabel={`Sign in with ${provider()}`}
                  onPress={() => auth.signIn(provider()).catch(() => {})}
                  class="text-primary"
                >
                  {`Sign in with ${provider()}`}
                </Text>
              )}
            </Each>
            <Text
              testID="sign-in-native-facebook"
              role="button"
              accessibilityLabel="Native-only sign in with Facebook"
              onPress={() => auth.signInNative("facebook").catch(() => {})}
              class="text-muted-foreground"
            >
              Native-only Facebook
            </Text>
          </View>
        }
      >
        {(current) => (
          <View class="gap-2">
            <Text testID="session-provider" class="text-foreground">{`provider ${current().provider}`}</Text>
            <If when={auth.user()}>
              {(who) => (
                <Text testID="user-name" class="text-foreground">{`user ${who().name ?? who().id}`}</Text>
              )}
            </If>
            <Text testID="session-scope" class="text-foreground">{`scope ${current().scope}`}</Text>
            <Text testID="session-expires" class="text-foreground">{`expires ${current().expiresAt}`}</Text>
            <Text
              testID="refresh"
              role="button"
              accessibilityLabel="Refresh"
              onPress={() => auth.refresh().catch(() => {})}
              class="text-primary"
            >
              Refresh
            </Text>
            <Text
              testID="refresh-8"
              role="button"
              accessibilityLabel="Refresh eight times"
              onPress={() => refreshEight()}
              class="text-primary"
            >
              Refresh 8x
            </Text>
            <Text
              testID="sign-out"
              role="button"
              accessibilityLabel="Sign out"
              onPress={() => auth.signOut().catch(() => {})}
              class="text-primary"
            >
              Sign out
            </Text>
          </View>
        )}
      </If>
      <Input
        testID="callback-url"
        accessibilityLabel="Callback URL"
        placeholder="paste the callback URL here"
        value={callbackDraft()}
        onChange={({ value }) => callbackDraft.set(value)}
        autoCapitalize="none"
        autoCorrect={false}
        class="rounded-(--radius) border border-input px-3 py-2"
      />
      <Text
        testID="submit-callback"
        role="button"
        accessibilityLabel="Use callback"
        onPress={() => submitCallback()}
        class="text-primary"
      >
        Use callback
      </Text>
    </View>
  );
}

mount(App);
