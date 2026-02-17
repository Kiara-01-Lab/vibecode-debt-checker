// ─── Structured JSON logger ───────────────────────────────────────
// Outputs newline-delimited JSON to stdout (info/warn) or stderr (error).
// 12-factor compatible — pipe to any log aggregator.

type Level = "info" | "warn" | "error";

function write(level: Level, event: string, data?: Record<string, unknown>) {
  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...data,
  });

  if (level === "error") {
    process.stderr.write(entry + "\n");
  } else {
    process.stdout.write(entry + "\n");
  }
}

export const log = {
  info: (event: string, data?: Record<string, unknown>) =>
    write("info", event, data),
  warn: (event: string, data?: Record<string, unknown>) =>
    write("warn", event, data),
  error: (event: string, data?: Record<string, unknown>) =>
    write("error", event, data),
};
