// Small app store: the contact email the form saves. Screens read it through
// these functions; the signal stays private.
import { signal } from "nsh";

const contactEmail = signal<string | null>(null);

/** The saved contact email, or null before the form saved one (tracked where read). */
export const contact = () => contactEmail();

/** Saves the contact email: the OIDC sign-in's login hint and the account's contact field. */
export function setContact(email: string) {
  contactEmail.set(email);
}
