import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    jwt: "src/jwt/index.ts",
    oauth: "src/oauth/index.ts",
    session: "src/session/index.ts",
    password: "src/password/index.ts",
    totp: "src/totp/index.ts",
    csrf: "src/csrf/index.ts",
    "api-key": "src/api-key/index.ts",
    "magic-link": "src/magic-link/index.ts",
    "rate-limit": "src/rate-limit/index.ts",
    middleware: "src/middleware/index.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  splitting: true,
  clean: true,
  treeshake: true,
  sourcemap: true,
  minify: false,
  target: "es2022",
  outDir: "dist",
});
