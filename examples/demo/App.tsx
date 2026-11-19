// One entry for every surface, the web included (nsh-query loads on the 0.6.0 web runtime).
import { mount } from "nsh";
import { createAppRoot } from "./src/app";
import { AccountScreen } from "./src/screens/account-screen";

mount(createAppRoot(AccountScreen));
