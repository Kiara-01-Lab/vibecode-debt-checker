import * as fs from "fs";
import * as path from "path";

// ─── Secret patterns to detect in source files ──────────────────
const SECRET_PATTERNS = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "AWS Secret Key", pattern: /(?:aws_secret|secret_key)\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/i },
  { name: "Stripe Secret", pattern: /sk_(live|test)_[0-9a-zA-Z]{24,}/ },
  { name: "Stripe Publishable (in .ts/.js)", pattern: /pk_(live|test)_[0-9a-zA-Z]{24,}/ },
  { name: "OpenAI Key", pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/ },
  { name: "Generic API Key Assignment", pattern: /(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-/.]{16,}["']/i },
  { name: "Private Key Block", pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/ },
  { name: "Database URL with password", pattern: /(?:postgres|mysql|mongodb):\/\/\w+:[^@\s]+@/ },
];

// Files to skip
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "__pycache__", ".venv"]);
const SCAN_EXTENSIONS = new Set([".ts", ".js", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".py", ".env.local"]);

interface Finding {
  file: string;
  line: number;
  pattern: string;
  preview: string;
}

function scanFile(filePath: string): Finding[] {
  const findings: Finding[] = [];
  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content.split("\n");

  // Skip .env and .env.example — those are supposed to have values
  const basename = path.basename(filePath);
  if (basename === ".env" || basename === ".env.example") return findings;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip comments
    if (line.trimStart().startsWith("//") || line.trimStart().startsWith("#")) continue;

    for (const { name, pattern } of SECRET_PATTERNS) {
      if (pattern.test(line)) {
        findings.push({
          file: filePath,
          line: i + 1,
          pattern: name,
          preview: line.trim().slice(0, 80) + (line.trim().length > 80 ? "..." : ""),
        });
      }
    }
  }
  return findings;
}

function walkDir(dir: string): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkDir(full));
    } else if (SCAN_EXTENSIONS.has(path.extname(entry.name))) {
      files.push(full);
    }
  }
  return files;
}

// ─── Check .gitignore includes .env ──────────────────────────────
function checkGitignore(root: string): string[] {
  const warnings: string[] = [];
  const gitignorePath = path.join(root, ".gitignore");

  if (!fs.existsSync(gitignorePath)) {
    warnings.push("⚠️  No .gitignore found — .env files may be committed!");
    return warnings;
  }

  const content = fs.readFileSync(gitignorePath, "utf-8");
  if (!content.includes(".env")) {
    warnings.push("⚠️  .gitignore does not include .env — secrets may be committed!");
  }
  return warnings;
}

// ─── Check .env.example drift ────────────────────────────────────
function checkEnvDrift(root: string): string[] {
  const warnings: string[] = [];
  const envPath = path.join(root, ".env");
  const examplePath = path.join(root, ".env.example");

  if (!fs.existsSync(examplePath)) {
    warnings.push("⚠️  No .env.example found — new contributors won't know what vars to set.");
    return warnings;
  }
  if (!fs.existsSync(envPath)) return warnings;

  const parseKeys = (content: string) =>
    content
      .split("\n")
      .filter((l) => l.includes("=") && !l.startsWith("#"))
      .map((l) => l.split("=")[0].trim());

  const envKeys = new Set(parseKeys(fs.readFileSync(envPath, "utf-8")));
  const exampleKeys = parseKeys(fs.readFileSync(examplePath, "utf-8"));

  for (const key of exampleKeys) {
    if (!envKeys.has(key)) {
      warnings.push(`⚠️  ${key} is in .env.example but missing from .env`);
    }
  }
  return warnings;
}

// ─── Run ─────────────────────────────────────────────────────────
function main() {
  const root = process.cwd();
  console.log("\n🔍 vibeguard security check\n");

  // 1. Gitignore check
  const gitWarnings = checkGitignore(root);
  for (const w of gitWarnings) console.log(w);

  // 2. Env drift check
  const driftWarnings = checkEnvDrift(root);
  for (const w of driftWarnings) console.log(w);

  // 3. Secret scan
  const files = walkDir(root);
  const allFindings: Finding[] = [];
  for (const file of files) {
    allFindings.push(...scanFile(file));
  }

  if (allFindings.length === 0 && gitWarnings.length === 0 && driftWarnings.length === 0) {
    console.log("✅ No issues found.\n");
    process.exit(0);
  }

  if (allFindings.length > 0) {
    console.log(`\n🚨 Found ${allFindings.length} potential secret(s) in source code:\n`);
    for (const f of allFindings) {
      console.log(`   ${f.file}:${f.line}`);
      console.log(`   Pattern: ${f.pattern}`);
      console.log(`   Preview: ${f.preview}\n`);
    }
    console.log("   Move these values to .env and reference via process.env.VAR_NAME\n");
  }

  process.exit(allFindings.length > 0 ? 1 : 0);
}

main();
