// The sign-in buttons' data: labels follow each provider's wording rules and the
// class strings are fixed (never built at run time) so `nsh build` checks them.
// Brand colors are theme tokens; which marks are drawn and why are in
// README.md under "Button marks and their limits".
export type ProviderId =
  | "google"
  | "facebook"
  | "discord"
  | "github"
  | "apple"
  | "microsoft"
  | "x"
  | "oidc"
  | "mock";

export interface ProviderMeta {
  id: ProviderId;
  label: string;
  buttonClass: string;
  labelClass: string;
}

export const PROVIDERS: ProviderMeta[] = [
  {
    id: "google",
    label: "Sign in with Google",
    buttonClass: "border border-provider-google-border bg-provider-google active:opacity-80",
    labelClass: "text-provider-google-foreground",
  },
  {
    id: "facebook",
    label: "Continue with Facebook",
    buttonClass: "bg-provider-facebook active:opacity-80",
    labelClass: "text-provider-facebook-foreground",
  },
  {
    id: "discord",
    label: "Continue with Discord",
    buttonClass: "bg-provider-discord active:opacity-80",
    labelClass: "text-provider-discord-foreground",
  },
  {
    id: "github",
    label: "Sign in with GitHub",
    buttonClass: "bg-provider-github active:opacity-80",
    labelClass: "text-provider-github-foreground",
  },
  {
    id: "apple",
    label: "Sign in with Apple",
    buttonClass: "bg-provider-apple active:opacity-80",
    // Apple's title rule: 43% of the button's height (44pt -> 19pt).
    labelClass: "text-[19px] font-semibold text-provider-apple-foreground",
  },
  {
    id: "microsoft",
    label: "Sign in with Microsoft",
    buttonClass: "bg-provider-microsoft active:opacity-80",
    labelClass: "text-provider-microsoft-foreground",
  },
  {
    id: "x",
    label: "Continue with X",
    buttonClass: "bg-provider-x active:opacity-80",
    labelClass: "text-provider-x-foreground",
  },
  {
    id: "oidc",
    label: "Sign in with OIDC",
    buttonClass: "border border-border bg-background active:bg-accent",
    labelClass: "text-foreground",
  },
  {
    id: "mock",
    label: "Sign in with Mock",
    buttonClass: "bg-primary active:bg-primary/90",
    labelClass: "text-primary-foreground",
  },
];

export function providerById(id: ProviderId): ProviderMeta {
  const meta = PROVIDERS.find((provider) => provider.id === id);
  if (!meta) throw new Error(`unknown provider ${id}`);
  return meta;
}
