// The app's text field: nsh/base's behavior once, with the demo's field look.
// Screens and forms import this, never nsh/base directly. Props forward one by
// one (a spread would leak `invalid` to the base element as an unknown prop).
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
      value={props.value}
      onChange={props.onChange}
      onSubmit={props.onSubmit}
      onBlur={props.onBlur}
      ref={props.ref}
      placeholder={props.placeholder}
      masked={props.masked}
      keyboardType={props.keyboardType}
      autoCapitalize={props.autoCapitalize}
      autoCorrect={props.autoCorrect}
      autoComplete={props.autoComplete}
      returnKeyType={props.returnKeyType}
      submitBehavior={props.submitBehavior}
      testID={props.testID}
      // Exactly one border color per state (stacking a second border-color
      // drops the border on real targets), and read inline: a body snapshot
      // would pin the border to the value it had at creation.
      class={`min-h-11 rounded-(--radius) border bg-background px-3 py-2 text-base text-foreground ${
        props.invalid ? "border-destructive focus:border-destructive" : "border-input focus:border-ring"
      } ${props.class ?? ""}`}
    />
  );
}
