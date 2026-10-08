import { useEffect, useState } from "react";
import App from "./App";
import { Landing } from "./components/Landing";

export function Root() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => { const update = () => setHash(window.location.hash); window.addEventListener("hashchange", update); return () => window.removeEventListener("hashchange", update); }, []);
  const tradingPath = /^\/(trade|app)(\/|$)/.test(window.location.pathname);
  return hash.startsWith("#/") || tradingPath ? <App /> : <Landing />;
}
