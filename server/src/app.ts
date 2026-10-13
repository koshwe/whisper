import { existsSync, mkdirSync } from "node:fs";
import { createServer as createHttpServer, type Server } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express, { type NextFunction, type Request, type Response } from "express";
import { openDatabase, type WhisperDb } from "./db.ts";
import { HttpError } from "./errors.ts";
import { registerRoutes } from "./routes.ts";
import { attachWebSocket } from "./ws.ts";

function serveClient(app: express.Express) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const clientDist = path.resolve(here, "../../client/dist");
  if (!existsSync(clientDist)) return;
  app.use(express.static(clientDist));
  app.use((req, res, next) => {
    if (req.method !== "GET" || req.path.startsWith("/api")) {
      next();
      return;
    }
    res.sendFile(path.join(clientDist, "index.html"));
  });
}

export function buildApp(db: WhisperDb, filesDir: string) {
  const app = express();
  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    next();
  });
  app.use(express.json({ limit: "1mb" }));
  registerRoutes(app, db, filesDir);
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "Not found." });
  });
  serveClient(app);
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof HttpError) {
      res.status(error.status).json({ error: error.message });
      return;
    }
    if (error && typeof error === "object" && "type" in error && (error as { type?: string }).type === "entity.too.large") {
      res.status(413).json({ error: "That file is larger than 8 MB." });
      return;
    }
    console.error(error);
    res.status(500).json({ error: "Something went wrong." });
  });
  return app;
}

export async function createServer(options: { dbPath: string; port: number }) {
  const db = openDatabase(options.dbPath);
  const filesDir = path.join(path.dirname(options.dbPath), "files");
  mkdirSync(filesDir, { recursive: true });
  const app = buildApp(db, filesDir);
  const server: Server = createHttpServer(app);
  attachWebSocket(server, db);
  await new Promise<void>((resolve) => {
    server.listen(options.port, "0.0.0.0", () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : options.port;
  return {
    port,
    db,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          db.close();
          if (error) reject(error);
          else resolve();
        });
      }),
  };
}
