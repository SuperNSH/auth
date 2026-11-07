// The provider marks a hand-built button can draw honestly (see README's
// "Button marks and their limits"): Microsoft's four squares are pure
// geometry; Facebook's f and the X mark are letterform approximations until
// the official assets ship. The rest draw nothing rather than fake a mark.
import { Text, View } from "nsh";
import type { ProviderId } from "../providers";

export function ProviderMark(props: { provider: ProviderId }) {
  switch (props.provider) {
    case "microsoft":
      return (
        <View accessibilityElementsHidden importantForAccessibility="no-hide-descendants" class="gap-0.5">
          <View class="flex-row gap-0.5">
            <View class="size-2 bg-provider-microsoft-red" />
            <View class="size-2 bg-provider-microsoft-green" />
          </View>
          <View class="flex-row gap-0.5">
            <View class="size-2 bg-provider-microsoft-blue" />
            <View class="size-2 bg-provider-microsoft-yellow" />
          </View>
        </View>
      );
    case "facebook":
      return (
        <Text
          accessibilityElementsHidden
          importantForAccessibility="no"
          class="text-xl leading-none font-bold text-provider-facebook-foreground"
        >
          f
        </Text>
      );
    case "x":
      return (
        <Text
          accessibilityElementsHidden
          importantForAccessibility="no"
          class="text-lg leading-none font-bold text-provider-x-foreground"
        >
          X
        </Text>
      );
    default:
      return null;
  }
}
