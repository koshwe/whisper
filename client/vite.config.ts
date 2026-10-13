import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import basicSsl from "@vitejs/plugin-basic-ssl";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const root = path.dirname(fileURLToPath(import.meta.url));

function certificateNames() {
  const names = new Set(["localhost"]);
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.internal || entry.family !== "IPv4") continue;
      names.add(entry.address);
    }
  }
  return [...names];
}

export default defineConfig({
  plugins: [react(), basicSsl({ name: "whisper", domains: certificateNames() })],
  resolve: {
    alias: {
      "@whisper/shared": path.resolve(root, "../shared/src/crypto.ts"),
    },
  },
  server: {
    host: true,
    port: 5173,
    fs: { allow: [path.resolve(root, "..")] },
    proxy: {
      "/api": "http://127.0.0.1:3001",
      "/ws": { target: "ws://127.0.0.1:3001", ws: true },
    },
  },
});
