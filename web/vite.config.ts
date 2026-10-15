import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The panel embeds the build (Task 21) and serves the Connect API under /api.
export default defineConfig({
  plugins: [react()],
  build: {
    // One bundle is served from the panel itself, to a handful of admins: it is
    // about 230 kB gzipped, and splitting it would not make a visit faster.
    chunkSizeWarningLimit: 1000,
  },
  server: {
    // `npm run dev` against a panel that runs on this machine (postern-panel serve).
    proxy: { "/api": "http://localhost:8080" },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    // A slow CI runner: findBy* waits up to 5 s (src/test/setup.ts), a test may chain a few.
    testTimeout: 15_000,
  },
});
