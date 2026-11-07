// The signed-in state's actions, presentational so the preview fixture can
// show the account screen's controls without touching the auth layer.
import { View } from "nsh";
import { Button } from "../ui/button";

export function AccountActions(props: { onRefresh: () => void; onSignOut: () => void }) {
  return (
    <View class="gap-2" testID="account-actions">
      <Button label="Refresh session" variant="outline" onPress={props.onRefresh} testID="refresh-session" />
      <Button label="Sign out" variant="danger" onPress={props.onSignOut} testID="sign-out" />
    </View>
  );
}
