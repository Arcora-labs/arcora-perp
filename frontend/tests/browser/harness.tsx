// Test-only entry; never included in the ordinary production build.
import React from "react";
import ReactDOM from "react-dom/client";
import App from "../../src/App";
import { RealDarkPerpClient } from "../../src/api/realClient";
import "../../src/styles.css";
const bootstrap = RealDarkPerpClient.bootstrap.bind(RealDarkPerpClient);
RealDarkPerpClient.bootstrap = async (...args) => {
  const client = await bootstrap(...args);
  Object.assign(window, { testClient: client });
  return client;
};
ReactDOM.createRoot(document.getElementById("root")!).render(<App />);
