import { defineConfig, mergeConfig } from "vite";
import viteConfig from "./vite.config";

// Vitest picks up this file over vite.config.ts, so merge the project's Vite
// config (React plugin, "@" alias, dependency dedupe) with test-only options.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      // Tests import from "vitest" explicitly; no globals needed.
      globals: false,
    },
  }),
);
