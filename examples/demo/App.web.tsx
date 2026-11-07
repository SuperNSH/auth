// Web entry: the web runtime cannot load nsh-query (its lifecycle import is
// missing there), so this mounts the query-free account screen variant.
// Build/bundle THIS entry for web surfaces; App.tsx is for native ones.
import { mount } from "nsh";
import { createAppRoot } from "./src/app";
import { AccountScreenWeb } from "./src/screens/account-screen.web";

mount(createAppRoot(AccountScreenWeb));
