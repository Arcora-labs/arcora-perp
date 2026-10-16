import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// Same rule as src/api/contractAddresses.ts, checked here so a malformed
// deploy-time contract address fails the build instead of the page.
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  for (const name of ["VITE_MOCK_USDC", "VITE_COLLATERAL_VAULT"]) {
    const value = env[name];
    if (value && !ADDRESS.test(value)) throw new Error(`${name} must be a 20-byte 0x address`);
  }
  return {
    plugins: [react()],
    server: { port: 5173 },
  };
});
