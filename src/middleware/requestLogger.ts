import { Request, Response, NextFunction } from "express";
import { log } from "../utils/logger";

// ─── Request logger middleware ────────────────────────────────────
// Logs every request as structured JSON on response finish.
// Captures method, path, status code, and duration in ms.

export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();

  res.on("finish", () => {
    log.info("request", {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      ms: Date.now() - start,
    });
  });

  next();
}
