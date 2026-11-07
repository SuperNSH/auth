// The app's text field: nsh/base's behavior once, with the demo's field look.
// Screens and forms import this, never nsh/base directly.
import { Input as BaseInput, type InputProps } from "nsh/base";

type FieldProps = Pick<
  InputProps,
  | "value"
  | "onChange"
  | "onSubmit"
  | "onBlur"
  | "ref"
  | "placeholder"
  | "masked"
  | "keyboardType"
  | "autoCapitalize"
  | "autoCorrect"
  | "autoComplete"
  | "returnKeyType"
  | "submitBehavior"
  | "testID"
>;

export function Input(props: FieldProps & { class?: string; invalid?: boolean }) {
  return (
    <BaseInput
      {...props}
      // Exactly one border color per state (stacking a second border-color
      // drops the border on real targets), and read inline: a body snapshot
      // would pin the border to the value it had at creation.
      class={`min-h-11 rounded-(--radius) border bg-background px-3 py-2 text-base text-foreground ${
        props.invalid ? "border-destructive focus:border-destructive" : "border-input focus:border-ring"
      } ${props.class ?? ""}`}
    />
  );
}
