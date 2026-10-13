import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "./app.ts";
import { loadEnv } from "./env.ts";

loadEnv();

const here = path.dirname(fileURLToPath(import.meta.url));
const volume = process.env.RAILWAY_VOLUME_MOUNT_PATH;
const dataDir = process.env.WHISPER_DB
  ? path.dirname(path.resolve(process.env.WHISPER_DB))
  : volume
    ? path.resolve(volume)
    : path.resolve(here, "../data");
mkdirSync(dataDir, { recursive: true });

const dbPath = process.env.WHISPER_DB ? path.resolve(process.env.WHISPER_DB) : path.join(dataDir, "whisper.sqlite");
const port = Number(process.env.PORT ?? 3001);
const started = await createServer({ dbPath, port });

console.log(`Whisper listening on http://0.0.0.0:${started.port}`);
