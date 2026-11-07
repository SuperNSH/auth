// The no-host fallback's return leg: with no embedding host, no redirect comes
// back by itself, so the user (or a page bridge via host.on("auth.redirect"))
// hands the callback URL to the package's handleRedirect.
import { signal, Text, View } from "nsh";
import { handleRedirect } from "../auth";
import { Input } from "../ui/input";
import { Button } from "../ui/button";

export function CallbackPasteBack() {
  const draft = signal("");
  const submit = () => {
    const url = draft().trim();
    if (!url) return;
    void handleRedirect(url).catch(() => {});
    draft.set("");
  };
  return (
    <View class="gap-2 rounded-(--radius) border border-border bg-card p-4" testID="paste-callback">
      <Text class="text-sm font-medium text-card-foreground">Finish a sign-in by hand</Text>
      <Text class="text-sm text-muted-foreground">
        No host is embedded, so no redirect returns by itself. Paste the callback URL the provider
        redirected to:
      </Text>
      <Input
        value={draft()}
        onChange={({ value }) => draft.set(value)}
        onSubmit={submit}
        placeholder="nsh.auth.sandbox://callback?code=…&state=…"
        autoCapitalize="none"
        autoCorrect={false}
        testID="callback-url"
      />
      <Button label="Finish sign-in" variant="outline" disabled={!draft().trim()} onPress={submit} testID="submit-callback" />
    </View>
  );
}
