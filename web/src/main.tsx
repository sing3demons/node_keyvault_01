import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { CallbackPage, LoginPage, VerifyEmailPage } from "./Login";
import "./styles.css";

const routes: Record<string, () => React.JSX.Element> = {
  "/login": LoginPage,
  "/callback": CallbackPage,
  "/verify-email": VerifyEmailPage
};
const Page = routes[location.pathname] ?? App;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Page />
  </StrictMode>
);
