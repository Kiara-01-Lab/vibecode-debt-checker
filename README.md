# vibeguard-starter

**Ship AI-generated code without the hidden risks.**
AIで生成したコードを、隠れたリスクなしで本番運用できるスターターキット。

---

## What This Does / これが解決する問題

AI tools generate code that *works* but has invisible problems: leaked API keys, no error handling, no logging, unvalidated inputs. You won't notice until production breaks.

This starter template has all four guardrails pre-wired. Clone it, start building, stay safe.

| Guard | What It Catches | Without This |
|-------|----------------|--------------|
| **Secret Protection** | API keys in source code | Your Stripe key ends up on GitHub |
| **Error Handling** | Unhandled crashes | Users see raw stack traces |
| **Input Validation** | Malicious/malformed input | SQL injection, XSS, crashes |
| **Structured Logging** | Every request + every error | Black box in production |

## Quick Start / クイックスタート

```bash
# Clone
git clone https://github.com/yourorg/vibeguard-starter.git my-app
cd my-app

# Setup
cp .env.example .env
npm install

# Run
npm run dev
```

Your server is running at `http://localhost:3000` with all guards active.

## Test It / 動作確認

```bash
# Health check
curl http://localhost:3000/health

# Create an item (input validation active)
curl -X POST http://localhost:3000/api/items \
  -H "Content-Type: application/json" \
  -d '{"name": "test item"}'

# Try invalid input (gets rejected with details)
curl -X POST http://localhost:3000/api/items \
  -H "Content-Type: application/json" \
  -d '{"name": ""}'

# Run security scan
npm run check
```

## Project Structure / プロジェクト構成

```
src/
├── index.ts              # App entry — everything wired here
├── routes/
│   └── items.ts          # Example CRUD route (replace with yours)
├── middleware/
│   ├── errorHandler.ts   # Global error catch → safe JSON responses
│   ├── requestLogger.ts  # Auto-logs every request as structured JSON
│   └── validate.ts       # Zod-based input validation middleware
└── utils/
    ├── env.ts            # Env validation — crashes fast if vars missing
    ├── logger.ts         # Structured JSON logger (stdout/stderr)
    └── check.ts          # Secret scanner (runs in CI too)
```

## Adding Your Own Routes / ルートの追加方法

```typescript
// src/routes/users.ts
import { Router } from "express";
import { z } from "zod";
import { validate, schemas } from "../middleware/validate";
import { AppError } from "../middleware/errorHandler";

const router = Router();

const createUserSchema = z.object({
  email: schemas.email,
  name: z.string().min(1).max(100).trim(),
});

router.post("/users", validate({ body: createUserSchema }), (req, res) => {
  // req.body is already validated and typed
  const { email, name } = req.body;
  // ... your logic here
  res.status(201).json({ email, name });
});

export default router;
```

Then register it in `src/index.ts`:
```typescript
import userRoutes from "./routes/users";
app.use("/api", userRoutes);
```

## CI Bot / CI ボット

The included GitHub Action (`.github/workflows/vibeguard.yml`) runs on every push and PR:

- Scans for hardcoded secrets
- Type-checks all TypeScript
- Verifies `.env.example` exists
- Checks `.gitignore` covers `.env`
- Warns about `eval()`, wildcard CORS, and `console.log`

No setup required — it works the moment you push to GitHub.

## Adding Environment Variables / 環境変数の追加

1. Add the variable to `.env.example` (with a placeholder value)
2. Add the variable to `.env` (with your real value)
3. Add validation in `src/utils/env.ts`:

```typescript
const envSchema = z.object({
  // ... existing vars
  DATABASE_URL: z.string().url(),
  STRIPE_SECRET_KEY: z.string().startsWith("sk_"),
});
```

The app will refuse to start if any required var is missing.

## License

MIT
