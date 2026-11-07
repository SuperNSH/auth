// Native entry: iOS, Android, macOS, Windows, Linux and headless runs.
// The web entry is App.web.tsx (nsh-query cannot load on the web runtime).
import { mount } from "nsh";
import { createAppRoot } from "./src/app";
import { AccountScreen } from "./src/screens/account-screen";

mount(createAppRoot(AccountScreen));
