import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "./app.ts";
import { loadEnv } from "./env.ts";

loadEnv();

const here = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(here, "../data");
mkdirSync(dataDir, { recursive: true });

const dbPath = process.env.WHISPER_DB ?? path.join(dataDir, "whisper.sqlite");
const port = Number(process.env.PORT ?? 3001);
const started = await createServer({ dbPath, port });

console.log(`Whisper listening on http://0.0.0.0:${started.port}`);
