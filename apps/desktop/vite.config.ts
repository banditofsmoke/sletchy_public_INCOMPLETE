import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The shipped window loads these files from inside the app, never from a server
// (ADR-0008). `npm run preview:browser` serves them on loopback for UI work only:
// in a browser there is no bridge, so the app runs on labelled preview data.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { host: "127.0.0.1", port: 1420, strictPort: true },
  build: { target: "es2022", sourcemap: false, outDir: "dist", emptyOutDir: true },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
