// One provider's sign-in button: brand colors, label and mark from the
// providers table. The accessibility label stays the plain wording even with a
// mark in front, so screen readers and tests hear one name.
import { providerById, type ProviderId } from "../providers";
import { ProviderMark } from "./provider-mark";
import { Button } from "../ui/button";

export function ProviderButton(props: { provider: ProviderId; disabled?: boolean; onPress: () => void }) {
  const meta = () => providerById(props.provider);
  return (
    <Button
      label={meta().label}
      icon={<ProviderMark provider={props.provider} />}
      disabled={props.disabled}
      onPress={props.onPress}
      class={meta().buttonClass}
      labelClass={meta().labelClass}
      testID={`provider-${props.provider}`}
    />
  );
}
