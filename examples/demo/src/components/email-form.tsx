// The contact email form: an nsh-form demo. The saved email shows as the
// account screen's contact field — nothing more (the package's signIn has no
// loginHint parameter yet; see the README).
import { Text, View } from "nsh";
import { createForm, inputProps } from "nsh-form";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { contact, setContact } from "../store";

// Mirrors the old required()+email() rule pair: empty is refused on submit,
// a malformed address is refused on change.
function emailError(value: string): string | undefined {
  if (!value) return "Enter your email";
  if (!value.includes("@")) return "That is not an email";
  return undefined;
}

export function EmailForm() {
  const form = createForm({
    defaultValues: { email: contact() ?? "" },
    onSubmit: async ({ value }) => {
      setContact(value.email.trim());
    },
  });
  return (
    <View class="gap-2" testID="email-form">
      <Text class="text-sm font-medium text-foreground">Contact email</Text>
      <form.Field
        name="email"
        validators={{
          onChange: ({ value }) => (value.includes("@") ? undefined : "That is not an email"),
          onSubmit: ({ value }) => emailError(value),
        }}
      >
        {(field) => (
          <View class="gap-2">
            <Input
              placeholder="you@example.com"
              keyboardType="email-address"
              autoCapitalize="none"
              autoCorrect={false}
              autoComplete="email"
              returnKeyType="done"
              submitBehavior="submit"
              testID="contact-email"
              invalid={field().state.meta.errors.length > 0}
              {...inputProps(field)}
            />
            <If when={field().state.meta.errors.length > 0}>
              {() => (
                <Text role="alert" class="text-sm text-destructive">
                  {String(field().state.meta.errors[0])}
                </Text>
              )}
            </If>
          </View>
        )}
      </form.Field>
      <Button label="Save email" variant="outline" onPress={() => void form.submit()} testID="save-email" />
      <If when={contact()}>
        {(saved) => <Text class="text-sm text-muted-foreground">{`Saved: ${saved()}`}</Text>}
      </If>
    </View>
  );
}
