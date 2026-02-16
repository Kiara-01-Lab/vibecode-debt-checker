import { z } from "zod";
import * as fs from "fs";
import * as path from "path";

// ─── Define your env vars here ───────────────────────────────────
// Add new vars as your app grows. The app will refuse to start
// if any required var is missing — this is intentional.
const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "production", "test"])
    .default("development"),
  PORT: z.coerce.number().default(3000),

  // Add your own required vars below:
  // DATABASE_URL: z.string().url(),
  // STRIPE_SECRET_KEY: z.string().startsWith("sk_"),
  // OPENAI_API_KEY: z.string().min(1),
});

export type Env = z.infer<typeof envSchema>;

// ─── Validate on import ──────────────────────────────────────────
function loadEnv(): Env {
  // Warn if no .env file exists
  const envPath = path.resolve(process.cwd(), ".env");
  const examplePath = path.resolve(process.cwd(), ".env.example");

  if (!fs.existsSync(envPath) && fs.existsSync(examplePath)) {
    console.warn(
      "\n⚠️  No .env file found. Copy .env.example to .env and fill in your values:\n" +
        "   cp .env.example .env\n"
    );
  }

  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    console.error("\n❌ Environment validation failed:\n");
    for (const issue of result.error.issues) {
      console.error(`   ${issue.path.join(".")}: ${issue.message}`);
    }
    console.error(
      "\n   Check your .env file against .env.example for missing values.\n"
    );
    process.exit(1);
  }

  return result.data;
}

export const env = loadEnv();
