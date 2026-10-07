import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Root } from "./Root";
import { ErrorBoundary } from "./components/ErrorBoundary";
import "./styles.css";
// Imported LAST so the incoming design's token overrides win over the default
// `:root`. Empty by default — see theme.css for the drop-slot contract.
import "./theme.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary>
      <Root />
    </ErrorBoundary>
  </StrictMode>,
);
