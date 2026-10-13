import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "./app.ts";
import { loadEnv } from "./env.ts";

loadEnv();

const here = path.dirname(fileURLToPath(import.meta.url));
const legacyDb = path.resolve(here, "../data/whisper.sqlite");

function resolveDbPath() {
  if (process.env.WHISPER_DB) return path.resolve(process.env.WHISPER_DB);
  const volume = process.env.RAILWAY_VOLUME_MOUNT_PATH?.trim();
  if (volume) {
    const dir = path.resolve(volume);
    mkdirSync(dir, { recursive: true });
    const target = path.join(dir, "whisper.sqlite");
    if (!existsSync(target) && existsSync(legacyDb)) copyFileSync(legacyDb, target);
    return target;
  }
  const dataDir = path.resolve(here, "../data");
  mkdirSync(dataDir, { recursive: true });
  return path.join(dataDir, "whisper.sqlite");
}

const dbPath = resolveDbPath();
mkdirSync(path.dirname(dbPath), { recursive: true });
const port = Number(process.env.PORT ?? 3001);
const started = await createServer({ dbPath, port });

console.log(`Whisper listening on http://0.0.0.0:${started.port}`);
console.log(`Whisper data file: ${dbPath}`);
if (process.env.RAILWAY_PROJECT_ID && !process.env.RAILWAY_VOLUME_MOUNT_PATH && !process.env.WHISPER_DB) {
  console.error("No Railway volume is mounted, so accounts will be erased on the next deploy. Add a volume to this service.");
}
