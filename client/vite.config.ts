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

// Railway injects PORT and terminates TLS at its edge, so skip HTTPS there.
const onRailway = Boolean(process.env.PORT);

const apiTarget = process.env.API_TARGET || "http://127.0.0.1:3001";
const wsTarget = apiTarget.replace(/^http/, "ws");

const proxy = {
  "/api": apiTarget,
  "/ws": { target: wsTarget, ws: true },
};

export default defineConfig({
  plugins: [
    react(),
    ...(onRailway ? [] : [basicSsl({ name: "whisper", domains: certificateNames() })]),
  ],
  resolve: {
    alias: {
      "@whisper/shared": path.resolve(root, "../shared/src/crypto.ts"),
    },
  },
  server: {
    host: true,
    port: 5173,
    fs: { allow: [path.resolve(root, "..")] },
    proxy,
  },
  preview: {
    host: true,
    port: 5173,
    // Allow the Railway public domain; vite preview rejects unknown Host headers by default.
    allowedHosts: true,
    proxy,
  },
});
