import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDbPath } from "../src/data-path.ts";

function tempDir() {
  return mkdtempSync(path.join(tmpdir(), "whisper-data-"));
}

test("keeps the database on the Railway volume instead of an ephemeral path", () => {
  const root = tempDir();
  const volume = path.join(root, "volume");
  const legacy = path.join(root, "server", "data", "whisper.sqlite");
  mkdirSync(path.dirname(legacy), { recursive: true });
  writeFileSync(legacy, "accounts");
  const chosen = resolveDbPath({
    env: { RAILWAY_PROJECT_ID: "project", RAILWAY_VOLUME_MOUNT_PATH: volume, WHISPER_DB: legacy },
    legacyDb: legacy,
  });
  assert.equal(chosen, path.join(volume, "whisper.sqlite"));
  assert.equal(readFileSync(chosen, "utf8"), "accounts");
});

test("does not replace accounts already stored on the volume", () => {
  const root = tempDir();
  const volume = path.join(root, "volume");
  const legacy = path.join(root, "server", "data", "whisper.sqlite");
  const current = path.join(volume, "whisper.sqlite");
  mkdirSync(volume, { recursive: true });
  mkdirSync(path.dirname(legacy), { recursive: true });
  writeFileSync(current, "kept");
  writeFileSync(legacy, "new-empty");
  const chosen = resolveDbPath({
    env: { RAILWAY_PROJECT_ID: "project", RAILWAY_VOLUME_MOUNT_PATH: volume },
    legacyDb: legacy,
  });
  assert.equal(readFileSync(chosen, "utf8"), "kept");
});

test("uses /data on Railway when the volume mount path is missing", () => {
  const root = tempDir();
  const fallback = path.join(root, "data", "whisper.sqlite");
  const chosen = resolveDbPath({
    env: { RAILWAY_PROJECT_ID: "project", WHISPER_DB: path.join(root, "ephemeral.sqlite") },
    legacyDb: path.join(root, "missing.sqlite"),
    railwayFallback: fallback,
  });
  assert.equal(chosen, fallback);
  assert.equal(existsSync(path.dirname(fallback)), true);
});

test("keeps the local database beside the server when not on Railway", () => {
  const root = tempDir();
  const legacy = path.join(root, "whisper.sqlite");
  const chosen = resolveDbPath({ env: {}, legacyDb: legacy });
  assert.equal(chosen, legacy);
});
