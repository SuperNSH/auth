// An auth failure: the machine-readable code first, the human message under it.
import { Text, View } from "nsh";

export function ErrorBanner(props: { code: string; message?: string }) {
  return (
    <View role="alert" class="gap-1 rounded-(--radius) border border-destructive bg-destructive/10 p-3">
      <Text class="text-sm font-medium text-destructive">{props.code}</Text>
      <If when={props.message}>
        {(message) => <Text class="text-sm text-destructive">{message()}</Text>}
      </If>
    </View>
  );
}
