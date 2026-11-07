// Screenshot evidence for the styled layer. Headless draws nothing, so run on a
// real target:
//   nsh test look.test.tsx --target macos
// The screenshots are looked at by a person; a pass here proves only that they
// were taken.
import { open, test } from "nsh/test";
import { PREVIEW_USERINFO_URL } from "./src/dev/fixtures";

const OUT = "/Users/hmziq/fo/nsh-auth/docs/evidence/demo";

test("the demo UI pieces in both appearances", async () => {
  const app = await open("./preview.tsx", {
    clock: {},
    colorScheme: "light",
    network: {
      [`GET ${PREVIEW_USERINFO_URL}`]: {
        body: { sub: "user-1", name: "Preview User", email: "preview@example.com" },
      },
    },
  });
  await app.waitFor("role:button[Sign in with Mock]");
  try {
    await app.screenshot(`${OUT}/preview-light.png`);
  } catch (error) {
    // Headless: this rejection carries no code on 0.4.0, so match its message.
    if (!String(error).includes("needs a real platform")) throw error;
    console.log("look: skipped, screenshots need --target");
    return;
  }
  await app.scroll("id:content-scroll", 600);
  await app.waitFor("text:Refresh session");
  await app.screenshot(`${OUT}/preview-account-actions-light.png`);
  // 860pt of drag lands ~1630pt of offset (the drag overshoots ~1.9x):
  // one frame holds the actions row, profile, claims and the paste-back card.
  await app.scroll("id:content-scroll", -150);
  // Settle with the actions heading at the frame top: actions, profile, claims
  // and paste-back span ~1370pt, one viewport holds them together.
  await app.scroll("id:content-scroll", 210);
  await app.screenshot(`${OUT}/preview-profile-light.png`);
  await app.setColorScheme("dark");
  await app.screenshot(`${OUT}/preview-profile-dark.png`);
  await app.scroll("id:content-scroll", -1700);
  await app.screenshot(`${OUT}/preview-dark.png`);
  // The form's visible validation state: an invalid submit shows the helper
  // text and the destructive border.
  await app.type("id:contact-email", "not-an-email");
  await app.press("id:save-email");
  await app.waitFor("text:That is not an email");
  await app.screenshot(`${OUT}/preview-form-error.png`);
});
