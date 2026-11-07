// The auth error signal as a banner, shown on whichever screen is up.
import { authError } from "../auth";
import { ErrorBanner } from "../ui/error-banner";

export function AuthErrorBanner() {
  return (
    <If when={authError()}>
      {(error) => <ErrorBanner code={error().code} message={error().message} />}
    </If>
  );
}
