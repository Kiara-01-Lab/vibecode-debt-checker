import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

// ─── Types ────────────────────────────────────────────────────────
type Severity = "error" | "warning";
type Category = "secret" | "security" | "quality";

interface Pattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  fix: string;
}

interface Finding {
  file: string;
  line: number;
  category: Category;
  name: string;
  preview: string;
  severity: Severity;
  fix: string;
}

interface StructuralIssue {
  message: string;
  fix: string;
  severity: Severity;
}

// ─── Secret patterns ─────────────────────────────────────────────
const SECRET_PATTERNS: Pattern[] = [
  {
    name: "AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/,
    severity: "error",
    fix: "Move to .env → process.env.AWS_ACCESS_KEY_ID",
  },
  {
    name: "AWS Secret Key",
    pattern: /(?:aws_secret|secret_key)\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/i,
    severity: "error",
    fix: "Move to .env → process.env.AWS_SECRET_ACCESS_KEY",
  },
  {
    name: "Stripe Secret Key",
    pattern: /sk_(live|test)_[0-9a-zA-Z]{24,}/,
    severity: "error",
    fix: "Move to .env → process.env.STRIPE_SECRET_KEY",
  },
  {
    name: "Stripe Publishable Key",
    pattern: /pk_(live|test)_[0-9a-zA-Z]{24,}/,
    severity: "error",
    fix: "Move to .env → process.env.STRIPE_PUBLISHABLE_KEY",
  },
  {
    name: "OpenAI API Key",
    pattern: /sk-[a-zA-Z0-9]{20,}/,
    severity: "error",
    fix: "Move to .env → process.env.OPENAI_API_KEY",
  },
  {
    name: "GitHub Token",
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/,
    severity: "error",
    fix: "Move to .env → process.env.GITHUB_TOKEN",
  },
  {
    name: "Generic hardcoded secret",
    pattern: /(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-/.]{16,}["']/i,
    severity: "error",
    fix: "Move to .env and reference via process.env",
  },
  {
    name: "Private key block",
    pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/,
    severity: "error",
    fix: "Remove from codebase entirely — store in a secrets manager",
  },
  {
    name: "Database URL with credentials",
    pattern: /(?:postgres|mysql|mongodb):\/\/\w+:[^@\s]+@/,
    severity: "error",
    fix: "Move to .env → process.env.DATABASE_URL",
  },
];

// ─── Security patterns ────────────────────────────────────────────
const SECURITY_PATTERNS: Pattern[] = [
  {
    name: "SQL injection (template literal)",
    pattern: /`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^`]*\$\{/i,
    severity: "error",
    fix: "Use parameterised queries: db.query('SELECT * FROM t WHERE id = $1', [id])",
  },
  {
    name: "innerHTML assignment",
    pattern: /\.innerHTML\s*[+]?=(?!\s*["']\s*["'])/,
    severity: "error",
    fix: "Use textContent, or sanitise with DOMPurify before assigning innerHTML",
  },
  {
    name: "dangerouslySetInnerHTML",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\{/,
    severity: "warning",
    fix: "Sanitise the value with DOMPurify before passing to dangerouslySetInnerHTML",
  },
  {
    name: "TLS verification disabled",
    pattern: /rejectUnauthorized\s*:\s*false/,
    severity: "error",
    fix: "Remove rejectUnauthorized: false — it disables certificate validation entirely",
  },
  {
    name: "Weak hash algorithm (MD5/SHA1)",
    pattern: /createHash\s*\(\s*["'](?:md5|sha1)['"]\s*\)/i,
    severity: "error",
    fix: "Use SHA-256 or stronger: crypto.createHash('sha256')",
  },
  {
    name: "eval() usage",
    pattern: /\beval\s*\(/,
    severity: "error",
    fix: "Remove eval() — it executes arbitrary strings and is a critical injection vector",
  },
  {
    name: "Shell injection risk",
    pattern: /exec(?:Sync)?\s*\(`[^`]*\$\{/,
    severity: "error",
    fix: "Use execFile() with an argument array to prevent shell injection",
  },
  {
    name: "Path traversal risk",
    pattern: /(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\b|params\b|body\b|query\b)/,
    severity: "error",
    fix: "Validate paths against a safe base directory — never pass user input directly to fs functions",
  },
  {
    name: "Wildcard CORS origin",
    pattern: /origin\s*:\s*["']\*["']/,
    severity: "warning",
    fix: "Restrict CORS to specific domains: origin: ['https://yourdomain.com']",
  },
];

// ─── Code quality patterns ────────────────────────────────────────
const QUALITY_PATTERNS: Pattern[] = [
  {
    name: "TODO / FIXME comment",
    pattern: /\/\/\s*(?:TODO|FIXME|HACK|XXX)\b/i,
    severity: "warning",
    fix: "Resolve before shipping — AI frequently leaves these as unfinished placeholders",
  },
  {
    name: "TypeScript `any`",
    pattern: /(?::\s*any\b|as\s+any\b|<any>)/,
    severity: "warning",
    fix: "Replace with a specific type — `any` disables type safety on this path",
  },
  {
    name: "Hardcoded localhost URL",
    pattern: /["']https?:\/\/localhost/,
    severity: "warning",
    fix: "Move to an environment variable: process.env.API_URL",
  },
  {
    name: "Hardcoded IP address",
    pattern: /["']https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    severity: "warning",
    fix: "Move to an environment variable",
  },
  {
    name: "console.log in source",
    pattern: /\bconsole\.(log|warn|error)\s*\(/,
    severity: "warning",
    fix: "Use the structured logger: log.info() / log.warn() / log.error()",
  },
  {
    name: "process.exit() outside entry file",
    pattern: /\bprocess\.exit\s*\(/,
    severity: "warning",
    fix: "Throw an AppError instead — process.exit() bypasses cleanup and is hard to test",
  },
];

// ─── File traversal ───────────────────────────────────────────────
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", ".next", "__pycache__", ".venv", "coverage",
]);
const CODE_EXTENSIONS = new Set([".ts", ".js", ".tsx", ".jsx", ".py"]);
const ALL_EXTENSIONS = new Set([
  ...CODE_EXTENSIONS, ".json", ".yaml", ".yml", ".toml", ".env.local",
]);

// Entry files exempt from process.exit and some noise checks
const ENTRY_BASENAMES = new Set([
  "index.ts", "index.js", "main.ts", "main.js", "server.ts", "server.js",
]);
// This file itself is exempt from console.log and process.exit checks
const SELF = path.basename(__filename);

function walkDir(dir: string, extensions: Set<string>): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkDir(full, extensions));
    } else if (extensions.has(path.extname(entry.name))) {
      files.push(full);
    }
  }
  return files;
}

// ─── File scanner ─────────────────────────────────────────────────
function scanFile(filePath: string, root: string): Finding[] {
  const findings: Finding[] = [];
  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content.split("\n");
  const basename = path.basename(filePath);
  const relPath = path.relative(root, filePath);
  const isCodeFile = CODE_EXTENSIONS.has(path.extname(filePath));

  // .env and .env.example are allowed to have values
  if (basename === ".env" || basename === ".env.example") return findings;

  function applyPatterns(patterns: Pattern[], category: Category) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trimStart();

      // Skip comment lines for non-secret patterns
      if (
        category !== "secret" &&
        (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*"))
      ) continue;

      for (const { name, pattern, severity, fix } of patterns) {
        // Exempt this file from console/process checks
        if (basename === SELF && (name.includes("console") || name.includes("process.exit"))) continue;
        // Exempt entry files from process.exit check
        if (name.includes("process.exit") && ENTRY_BASENAMES.has(basename)) continue;

        if (pattern.test(line)) {
          findings.push({
            file: relPath,
            line: i + 1,
            category,
            name,
            severity,
            fix,
            preview: line.trim().slice(0, 100) + (line.trim().length > 100 ? "..." : ""),
          });
        }
      }
    }
  }

  applyPatterns(SECRET_PATTERNS, "secret");

  // Skip security/quality on this file — pattern strings self-match
  if (basename === SELF) return findings;

  // Security and quality only apply to code files
  if (isCodeFile) {
    applyPatterns(SECURITY_PATTERNS, "security");
    applyPatterns(QUALITY_PATTERNS, "quality");

    // ── JWT without expiry (multi-line) ──
    for (let i = 0; i < lines.length; i++) {
      if (/\bjwt\.sign\s*\(/.test(lines[i])) {
        const window = lines.slice(i, i + 6).join(" ");
        if (!/expiresIn/.test(window)) {
          findings.push({
            file: relPath,
            line: i + 1,
            category: "security",
            name: "JWT signed without expiry",
            severity: "warning",
            fix: "Add expiresIn: jwt.sign(payload, secret, { expiresIn: '1h' })",
            preview: lines[i].trim().slice(0, 100),
          });
        }
      }
    }
  }

  return findings;
}

// ─── Structural checks ────────────────────────────────────────────
function checkGitignore(root: string): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  const gitignorePath = path.join(root, ".gitignore");

  if (!fs.existsSync(gitignorePath)) {
    issues.push({
      message: "No .gitignore found — .env files may be committed",
      fix: 'Create .gitignore and add ".env" to it',
      severity: "error",
    });
    return issues;
  }

  const content = fs.readFileSync(gitignorePath, "utf-8");
  if (!content.includes(".env")) {
    issues.push({
      message: ".gitignore does not include .env",
      fix: 'Add ".env" to .gitignore',
      severity: "error",
    });
  }
  return issues;
}

function checkEnvDrift(root: string): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  const envPath = path.join(root, ".env");
  const examplePath = path.join(root, ".env.example");

  if (!fs.existsSync(examplePath)) {
    issues.push({
      message: "No .env.example found — contributors won't know which vars to set",
      fix: "Create .env.example with placeholder values for every required variable",
      severity: "warning",
    });
    return issues;
  }
  if (!fs.existsSync(envPath)) return issues;

  const parseKeys = (c: string) =>
    c.split("\n")
      .filter((l) => l.includes("=") && !l.startsWith("#"))
      .map((l) => l.split("=")[0].trim());

  const envKeys = new Set(parseKeys(fs.readFileSync(envPath, "utf-8")));
  const exampleKeys = parseKeys(fs.readFileSync(examplePath, "utf-8"));

  for (const key of exampleKeys) {
    if (!envKeys.has(key)) {
      issues.push({
        message: `"${key}" is in .env.example but missing from .env`,
        fix: `Add ${key}=<value> to your .env file`,
        severity: "warning",
      });
    }
  }
  return issues;
}

function checkSecurityMiddleware(files: string[]): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  const allContent = files.map((f) => fs.readFileSync(f, "utf-8")).join("\n");

  if (!/\bhelmet\s*\(\s*\)/.test(allContent)) {
    issues.push({
      message: "helmet() not found — HTTP security headers are not set",
      fix: "npm install helmet, then add app.use(helmet()) in your entry file",
      severity: "warning",
    });
  }

  if (!/rateLimit\s*\(/.test(allContent) && !allContent.includes("express-rate-limit")) {
    issues.push({
      message: "No rate limiting found — API is vulnerable to brute-force attacks",
      fix: "npm install express-rate-limit, then add app.use(rateLimit({ windowMs, max }))",
      severity: "warning",
    });
  }

  return issues;
}

function checkAsyncHandlers(files: string[], root: string): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  const routeFiles = files.filter(
    (f) => !ENTRY_BASENAMES.has(path.basename(f))
  );

  for (const file of routeFiles) {
    const content = fs.readFileSync(file, "utf-8");
    const hasAsync =
      /async\s*\(\s*(?:req|request)/.test(content) ||
      /async\s+function\b[^(]*\(\s*(?:req|request)/.test(content);

    if (!hasAsync) continue;

    const hasTryCatch = /\btry\s*\{/.test(content);
    const hasCatch = /\.catch\s*\(/.test(content);
    const hasNextErr = /next\s*\(\s*(?:err|error|e)\b/.test(content);

    if (!hasTryCatch && !hasCatch && !hasNextErr) {
      issues.push({
        message: `${path.relative(root, file)} has async handlers with no error forwarding`,
        fix: "Wrap with try/catch and call next(err), or use an asyncHandler wrapper",
        severity: "warning",
      });
    }
  }
  return issues;
}

function checkPackageJson(root: string): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  const pkgPath = path.join(root, "package.json");
  if (!fs.existsSync(pkgPath)) return issues;

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));

  if (!pkg.engines?.node) {
    issues.push({
      message: 'package.json missing "engines.node" — Node version is unspecified',
      fix: 'Add "engines": { "node": ">=18" } to package.json',
      severity: "warning",
    });
  }

  const devOnlyPkgs = [
    "tsx", "typescript", "ts-node", "nodemon",
    "jest", "vitest", "eslint", "prettier", "ts-jest",
  ];
  const deps = Object.keys(pkg.dependencies || {});

  for (const d of devOnlyPkgs) {
    if (deps.includes(d)) {
      issues.push({
        message: `"${d}" is in dependencies — it should be in devDependencies`,
        fix: `Move ${d} to devDependencies (only needed at build time)`,
        severity: "warning",
      });
    }
  }

  for (const d of deps) {
    if (d.startsWith("@types/")) {
      issues.push({
        message: `"${d}" is in dependencies — type packages belong in devDependencies`,
        fix: `Move ${d} to devDependencies`,
        severity: "warning",
      });
    }
  }

  return issues;
}

function checkNpmAudit(root: string): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  try {
    execSync("npm audit --json", { cwd: root, stdio: ["ignore", "pipe", "ignore"] });
    // exit 0 → no vulnerabilities
  } catch (e: any) {
    try {
      const output: string = e.stdout?.toString() || "";
      if (!output) return issues;
      const audit = JSON.parse(output);
      const v = audit.metadata?.vulnerabilities ?? {};
      const critical: number = v.critical ?? 0;
      const high: number = v.high ?? 0;
      const moderate: number = v.moderate ?? 0;

      if (critical > 0 || high > 0) {
        issues.push({
          message: `npm audit: ${critical} critical, ${high} high severity vulnerabilities in dependencies`,
          fix: "Run npm audit fix to patch automatically, then review the rest",
          severity: "error",
        });
      } else if (moderate > 0) {
        issues.push({
          message: `npm audit: ${moderate} moderate severity vulnerabilities in dependencies`,
          fix: "Run npm audit for details and npm audit fix to patch",
          severity: "warning",
        });
      }
    } catch {
      // Could not parse audit output — skip silently
    }
  }
  return issues;
}

// ─── Output helpers ───────────────────────────────────────────────
const BOLD  = (s: string) => `\x1b[1m${s}\x1b[0m`;
const RED   = (s: string) => `\x1b[31m${s}\x1b[0m`;
const YELLOW = (s: string) => `\x1b[33m${s}\x1b[0m`;
const GREEN = (s: string) => `\x1b[32m${s}\x1b[0m`;
const DIM   = (s: string) => `\x1b[2m${s}\x1b[0m`;

function section(title: string, count: number) {
  const bar = "─".repeat(Math.max(0, 52 - title.length - String(count).length));
  console.log(`\n${BOLD(`── ${title} (${count})`)} ${DIM(bar)}`);
}

function printFinding(f: Finding) {
  const icon = f.severity === "error" ? RED("🚨") : YELLOW("⚠️ ");
  console.log(`  ${icon} ${BOLD(f.file)}:${f.line}  ${DIM(f.name)}`);
  console.log(`     Preview : ${f.preview}`);
  console.log(`     Fix     : ${f.fix}\n`);
}

function printIssue(w: StructuralIssue) {
  const icon = w.severity === "error" ? RED("🚨") : YELLOW("⚠️ ");
  console.log(`  ${icon} ${w.message}`);
  console.log(`     Fix : ${w.fix}\n`);
}

// ─── Main ─────────────────────────────────────────────────────────
function main() {
  // Accept optional root path as CLI arg (used by GitHub Action)
  const root = process.argv[2]
    ? path.resolve(process.argv[2])
    : process.cwd();

  console.log(BOLD("\n🔍 vibeguard — security & quality check\n"));

  const structuralIssues: StructuralIssue[] = [];

  // ── Structural checks ──────────────────────────────────────────
  structuralIssues.push(...checkGitignore(root));
  structuralIssues.push(...checkEnvDrift(root));
  structuralIssues.push(...checkPackageJson(root));
  structuralIssues.push(...checkNpmAudit(root));

  // ── File scan ──────────────────────────────────────────────────
  const allFiles = walkDir(root, ALL_EXTENSIONS);
  const codeFiles = allFiles.filter((f) => CODE_EXTENSIONS.has(path.extname(f)));

  structuralIssues.push(...checkSecurityMiddleware(codeFiles));
  structuralIssues.push(...checkAsyncHandlers(codeFiles, root));

  const allFindings: Finding[] = [];
  for (const file of allFiles) {
    allFindings.push(...scanFile(file, root));
  }

  // ── Nothing found ──────────────────────────────────────────────
  if (allFindings.length === 0 && structuralIssues.length === 0) {
    console.log(GREEN("✅ No issues found.\n"));
    process.exit(0);
  }

  // ── Print by category ──────────────────────────────────────────
  const secrets  = allFindings.filter((f) => f.category === "secret");
  const security = allFindings.filter((f) => f.category === "security");
  const quality  = allFindings.filter((f) => f.category === "quality");

  if (secrets.length > 0) {
    section("Secrets", secrets.length);
    secrets.forEach(printFinding);
  }
  if (security.length > 0) {
    section("Security", security.length);
    security.forEach(printFinding);
  }
  if (quality.length > 0) {
    section("Code Quality", quality.length);
    quality.forEach(printFinding);
  }
  if (structuralIssues.length > 0) {
    section("Structure & Config", structuralIssues.length);
    structuralIssues.forEach(printIssue);
  }

  // ── Summary ────────────────────────────────────────────────────
  const errorCount = [
    ...allFindings.filter((f) => f.severity === "error"),
    ...structuralIssues.filter((i) => i.severity === "error"),
  ].length;
  const warnCount = [
    ...allFindings.filter((f) => f.severity === "warning"),
    ...structuralIssues.filter((i) => i.severity === "warning"),
  ].length;

  const bar = "─".repeat(48);
  console.log(`${DIM(bar)}`);
  const errStr  = errorCount > 0 ? RED(`${errorCount} error(s)`) : `${errorCount} error(s)`;
  const warnStr = warnCount  > 0 ? YELLOW(`${warnCount} warning(s)`) : `${warnCount} warning(s)`;
  console.log(`  ${errStr}   ${warnStr}\n`);

  process.exit(errorCount > 0 ? 1 : 0);
}

main();
