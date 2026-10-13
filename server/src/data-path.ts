import { copyFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import path from "node:path";

function fileSize(file: string) {
  if (!existsSync(file)) return 0;
  try {
    return statSync(file).size;
  } catch {
    return 0;
  }
}

function isInside(parent: string, child: string) {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function copyDatabase(source: string, target: string) {
  mkdirSync(path.dirname(target), { recursive: true });
  if (existsSync(target)) return;
  copyFileSync(source, target);
  for (const suffix of ["-wal", "-shm"]) {
    if (existsSync(source + suffix)) copyFileSync(source + suffix, target + suffix);
  }
}

export function resolveDbPath(options: { env: NodeJS.ProcessEnv; legacyDb: string; railwayFallback?: string }) {
  const railway = Boolean(options.env.RAILWAY_PROJECT_ID || options.env.RAILWAY_ENVIRONMENT_ID || options.env.RAILWAY_SERVICE_ID);
  const volume = options.env.RAILWAY_VOLUME_MOUNT_PATH?.trim();
  const explicit = options.env.WHISPER_DB?.trim() ? path.resolve(options.env.WHISPER_DB) : "";
  const fallback = options.railwayFallback ?? "/data/whisper.sqlite";
  let canonical = options.legacyDb;
  if (volume) {
    const volumeDir = path.resolve(volume);
    canonical = explicit && isInside(volumeDir, explicit) ? explicit : path.join(volumeDir, "whisper.sqlite");
  } else if (explicit && !railway) {
    canonical = explicit;
  } else if (railway) {
    canonical = fallback;
  } else if (explicit) {
    canonical = explicit;
  }

  mkdirSync(path.dirname(canonical), { recursive: true });
  if (fileSize(canonical) === 0) {
    const sources = [options.legacyDb, "/app/server/data/whisper.sqlite", "/app/data/whisper.sqlite", explicit].filter(
      (file): file is string => Boolean(file) && path.resolve(file) !== path.resolve(canonical) && fileSize(file) > 0,
    );
    const source = sources[0];
    if (source) copyDatabase(source, canonical);
  }
  return canonical;
}
