import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  // the API reads PORT from the repo's .env (dotenv); Vite does not put .env into process.env, so load it here
  // (all keys, from the repo root — `root` below is ./web)
  const env = { ...loadEnv(mode, process.cwd(), ""), ...process.env };
  const apiTarget = `http://localhost:${env.PORT ?? 3001}`; // same default as src/config.ts

  return {
    root: "web",
    plugins: [react()],
    build: {
      outDir: "../dist/public",
      emptyOutDir: true
    },
    server: {
      port: 5173,
      proxy: {
        "/secrets": apiTarget,
        "/health": apiTarget,
        "/oauth": apiTarget,
        "/auth": apiTarget,
        "/admin": apiTarget,
        "/.well-known": apiTarget
      }
    }
  };
});
