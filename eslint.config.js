import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier/flat";

export default tseslint.config(
  { ignores: ["dist", "src/convex/_generated/**"] },
  {
    extends: [
      js.configs.recommended,
      ...tseslint.configs.recommended,
      eslintConfigPrettier,
    ],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Off by design: this rule is a Fast-Refresh DX hint, and this project
      // runs on a platform with managed/disabled HMR where it never fires.
      // Several files are also intentionally shared modules (the SOC state
      // engine, shared UI primitives, shadcn-style variant consts) and the
      // read-only platform toolbar file cannot be restructured, so the rule
      // cannot be satisfied without high-risk churn for zero runtime benefit.
      "react-refresh/only-export-components": "off",
    },
  },
);
