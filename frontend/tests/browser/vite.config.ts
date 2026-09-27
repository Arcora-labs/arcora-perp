import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  define: { "import.meta.env.VITE_API_URL": JSON.stringify("same-origin") },
  build: { outDir: "output/playwright/build", rollupOptions: { input: "tests/browser/index.html" } },
});
