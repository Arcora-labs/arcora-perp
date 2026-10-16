import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// Same rule as src/api/contractAddresses.ts, checked once the env is resolved
// so a malformed deploy-time contract address fails the build instead of the
// page. A plugin (not a config callback) keeps this config mergeable by
// vitest.config.ts.
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function contractAddressGuard(): Plugin {
  return {
    name: "arcora-contract-address-guard",
    configResolved(config) {
      for (const name of ["VITE_MOCK_USDC", "VITE_COLLATERAL_VAULT"]) {
        const value = config.env[name];
        if (value && !ADDRESS.test(value)) throw new Error(`${name} must be a 20-byte 0x address`);
      }
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), contractAddressGuard()],
  server: { port: 5173 },
});
