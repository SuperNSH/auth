// The contact email form: an nsh-form demo. The saved email shows as the
// account screen's contact field — nothing more (the package's signIn has no
// loginHint parameter yet; see the README).
import { Text, View } from "nsh";
import { createForm, email, required } from "nsh-form";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { contact, setContact } from "../store";

export function EmailForm() {
  const form = createForm({
    initial: { email: contact() ?? "" },
    onSubmit: async (values) => {
      setContact(values.email.trim());
    },
  });
  const address = form.field("email", {
    rules: [required("Enter your email"), email("That is not an email")],
  });
  return (
    <View class="gap-2" testID="email-form">
      <Text class="text-sm font-medium text-foreground">Contact email</Text>
      <Input
        placeholder="you@example.com"
        keyboardType="email-address"
        autoCapitalize="none"
        autoCorrect={false}
        autoComplete="email"
        returnKeyType="done"
        submitBehavior="submit"
        testID="contact-email"
        invalid={Boolean(address.error())}
        {...address.inputProps()}
      />
      <If when={address.error()}>
        {(message) => <Text role="alert" class="text-sm text-destructive">{message()}</Text>}
      </If>
      <Button label="Save email" variant="outline" onPress={() => void form.submit()} testID="save-email" />
      <If when={contact()}>
        {(saved) => <Text class="text-sm text-muted-foreground">{`Saved: ${saved()}`}</Text>}
      </If>
    </View>
  );
}
