import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies the API to a local uvicorn on :8000.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
  server: {
    proxy: { "/api": "http://127.0.0.1:8000", "/auth": "http://127.0.0.1:8000" },
  },
});
