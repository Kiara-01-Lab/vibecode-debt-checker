Top 4 most solvable via an OSS API/SDK, ranked by impact × feasibility:

**1. Hardcoded secrets / no env management (#41)**
Dead simple to detect and fix programmatically. A SDK that scans, warns, and auto-migrates to `.env` patterns. Near-zero false positives. Vibe coders get immediate value: "you're about to push your Stripe key to GitHub" — they understand that in 3 seconds.

**2. No input validation (#42)**
A schema-first validation SDK (think Zod but opinionated and auto-suggested). You can infer what needs validation from route handlers and form inputs. The SDK generates validators from existing code patterns. Solves the "works when you use it nicely" problem without requiring the developer to know *what* to validate.

**3. No error handling (#12)**
A middleware/wrapper SDK that auto-catches unhandled errors, logs them structured, and returns safe responses. The vibe coder wraps their app in one function call and gets production-grade error handling. Think Sentry-lite but as a library, not a SaaS. The key: it works with zero configuration.

**4. No monitoring/logging (#33)**
Closely paired with #3. An SDK that auto-instruments routes, DB calls, and external API calls with structured logging. Zero-config, one-line setup. Outputs to stdout (12-factor compatible) with optional dashboard. Turns the black box transparent.

**Why these 4:**
- All detectable/fixable without understanding the codebase's business logic
- All solvable with a single `npm install` / `pip install` + one line of init code
- All produce immediate visible value (the mom test: "it catches your mistakes before users see them")
- All are horizontal — they work regardless of what the vibe coder is building

The unifying product narrative: **"guardrails for AI-generated code."**
