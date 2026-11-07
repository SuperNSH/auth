import { signal, Text, View } from "nsh";

mount(() => {
  const status = signal("importing…");
  void (async () => {
    try {
      const module = await import("./src/ui/profile-card");
      status.set(`import ok: ${typeof module.createProfileQuery}`);
    } catch (error) {
      status.set(`import rejected: ${String(error).slice(0, 70)}`);
    }
  })();
  return (
    <View class="flex-1 bg-background p-4">
      <Text class="text-foreground" testID="probe-status">{`PROBE G ${status()}`}</Text>
    </View>
  );
});
