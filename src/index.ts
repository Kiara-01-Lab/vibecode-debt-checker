import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";

import { env } from "./utils/env";
import { log } from "./utils/logger";
import { requestLogger } from "./middleware/requestLogger";
import { errorHandler } from "./middleware/errorHandler";
import itemRoutes from "./routes/items";

const app = express();

// ─── Security defaults ───────────────────────────────────────────
app.use(helmet());
app.use(
  cors({
    origin: env.NODE_ENV === "production"
      ? false // Lock down in production — set your allowed origins
      : true,
  })
);
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// ─── Body parsing ────────────────────────────────────────────────
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

// ─── Logging ─────────────────────────────────────────────────────
app.use(requestLogger);

// ─── Routes ──────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.use("/api", itemRoutes);

// ─── Error handler (must be LAST) ────────────────────────────────
app.use(errorHandler);

// ─── Start ───────────────────────────────────────────────────────
app.listen(env.PORT, () => {
  log.info("server_started", {
    port: env.PORT,
    env: env.NODE_ENV,
  });
});

export default app;
