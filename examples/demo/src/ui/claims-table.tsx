// The tokens readout: id_token claims as rows, plus what the session holds. The
// auth layer (or a test) hands the claims in; this file knows no nsh-auth.
import { Text, View } from "nsh";

export function ClaimsTable(props: {
  claims: Record<string, unknown> | null;
  accessTokenTail?: string | null;
  refreshTokenPresent?: boolean;
}) {
  return (
    <View class="gap-2 rounded-(--radius) border border-border bg-card p-4">
      <Text class="text-sm font-medium text-card-foreground">ID token claims</Text>
      <If when={props.claims} else={<Text class="text-sm text-muted-foreground">No ID token in this session.</Text>}>
        {() => (
          <View class="gap-1">
            <Each of={claimsToRows(props.claims)} key={(row) => row.key}>
              {(row) => (
                <View class="flex-row items-start justify-between gap-3">
                  <Text class="text-sm text-muted-foreground">{row().key}</Text>
                  <Text class="flex-1 text-right text-sm tabular-nums text-card-foreground">{row().value}</Text>
                </View>
              )}
            </Each>
          </View>
        )}
      </If>
      <View class="mt-1 gap-1 border-t border-border pt-2">
        <Text class="text-sm text-muted-foreground">
          Access token: {props.accessTokenTail ? `…${props.accessTokenTail}` : "none"}
        </Text>
        <Text class="text-sm text-muted-foreground">
          Refresh token: {props.refreshTokenPresent ? "stored" : "none"}
        </Text>
      </View>
    </View>
  );
}

/** Epoch-second claims read as dates; `aud` lists may be arrays. */
export function claimsToRows(claims: Record<string, unknown> | null): { key: string; value: string }[] {
  if (!claims) return [];
  const keys = ["iss", "aud", "sub", "nonce", "exp", "iat", "name", "email"];
  return keys
    .filter((key) => claims[key] !== undefined)
    .map((key) => ({ key, value: claimText(claims[key]) }));
}

function claimText(value: unknown): string {
  if (typeof value === "number") return new Date(value * 1000).toISOString();
  if (Array.isArray(value)) return value.map(String).join(", ");
  return String(value);
}
