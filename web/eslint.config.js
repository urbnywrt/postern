import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig([
  // src/gen is the output of protoc-gen-es (npm run gen).
  globalIgnores(["dist", "coverage", "src/gen"]),
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      tseslint.configs.strictTypeChecked,
      tseslint.configs.stylisticTypeChecked,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2023,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": "error",
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@mantine/core",
              importNames: ["PasswordInput"],
              message:
                "Use PasswordField: it names the show button and puts it in the tab order, which Mantine's own does not.",
            },
          ],
        },
      ],
      // What the panel sends is shown as text, and an image is shown as an image (see
      // qrDataUri): nothing that comes from the network goes into the page as markup.
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Do not put markup into the page. The QR code is an <img> with a data: address (qrDataUri).",
        },
        {
          selector: "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]",
          message: "Do not put markup into the page.",
        },
      ],
    },
  },
  {
    // The one place that wraps Mantine's field.
    files: ["src/components/PasswordField.tsx"],
    rules: { "no-restricted-imports": "off" },
  },
  {
    // Configuration files run in Node and are not part of the TypeScript project.
    files: ["**/*.js"],
    extends: [js.configs.recommended, tseslint.configs.disableTypeChecked],
    languageOptions: { globals: globals.node },
  },
]);
