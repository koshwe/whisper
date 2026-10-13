import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "./app.ts";
import { resolveDbPath } from "./data-path.ts";
import { loadEnv } from "./env.ts";

loadEnv();

const here = path.dirname(fileURLToPath(import.meta.url));
const legacyDb = path.resolve(here, "../data/whisper.sqlite");
const dbPath = resolveDbPath({ env: process.env, legacyDb });
const port = Number(process.env.PORT ?? 3001);
const alreadyThere = existsSync(dbPath) && statSync(dbPath).size > 0;
const started = await createServer({ dbPath, port });

console.log(`Whisper listening on http://0.0.0.0:${started.port}`);
console.log(`Whisper data file: ${dbPath}${alreadyThere ? " (existing accounts)" : " (new database)"}`);
if ((process.env.RAILWAY_PROJECT_ID || process.env.RAILWAY_ENVIRONMENT_ID) && !process.env.RAILWAY_VOLUME_MOUNT_PATH) {
  console.error("No Railway volume is mounted. Mount one at /data before the next deploy, or accounts will be erased again.");
}
