// The app's button: nsh/base's behavior once, with the app's look. Screens import
// this, never nsh/base directly.
import { Text, type JSX } from "nsh";
import { Button as BaseButton } from "nsh/base";

const variants = {
  primary: "bg-primary",
  outline: "border border-border bg-background",
  danger: "bg-destructive",
};

const labels = {
  primary: "text-primary-foreground",
  outline: "text-foreground",
  danger: "text-destructive-foreground",
};

const active = {
  primary: "active:bg-primary/90",
  outline: "active:bg-accent",
  danger: "active:bg-destructive/90",
};

export function Button(props: {
  label: string;
  variant?: keyof typeof variants;
  disabled?: boolean;
  onPress?: () => void;
  icon?: JSX.Element;
  /** Extra classes, appended after the variant (a provider's brand colors). */
  class?: string;
  /** Overrides the variant's label color (a provider's brand foreground). */
  labelClass?: string;
  testID?: string;
}) {
  const variant = () => props.variant ?? "primary";
  return (
    <BaseButton
      disabled={props.disabled}
      onPress={props.onPress}
      testID={props.testID}
      // The plain wording is the accessible name, whatever mark sits in front.
      accessibilityLabel={props.label}
      class={`min-h-11 flex-row items-center justify-center gap-2 rounded-(--radius) px-4 py-2 transition-colors focus:outline-2 focus:outline-ring disabled:opacity-50 ${variants[variant()]} ${active[variant()]} ${props.class ?? ""}`}
    >
      {props.icon}
      <Text class={`text-sm font-medium ${props.labelClass ?? labels[variant()]}`}>{props.label}</Text>
    </BaseButton>
  );
}
