import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const apiTarget = `http://localhost:${process.env.PORT ?? 3000}`;

export default defineConfig({
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
      "/health": apiTarget
    }
  }
});
