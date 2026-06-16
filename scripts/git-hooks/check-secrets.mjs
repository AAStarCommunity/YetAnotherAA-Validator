// Pre-commit secret scanner — blocks committing secret files / obvious credentials.
// Installed via `git config core.hooksPath scripts/git-hooks` (package.json "prepare").
// Exits non-zero to abort the commit when a likely secret is staged.
import { execSync } from "child_process";

const staged = execSync("git diff --cached --name-only --diff-filter=ACM", { encoding: "utf8" })
  .split("\n")
  .map(s => s.trim())
  .filter(Boolean);

const problems = [];

// 1. Secret FILES that must never be committed (the .env.sepolia incident).
const SECRET_FILE =
  /(^|\/)(\.env(\.[\w.-]+)?|notify-contacts\.json|node_(state|dev_\d+|[0-9a-f]+)\.json|.*\.key|.*\.pem)$/i;
const ALLOWED = /\.example(\.\w+)?$|\.sample$/i; // *.example / *.sample are templates
for (const f of staged) {
  if (SECRET_FILE.test(f) && !ALLOWED.test(f)) {
    problems.push(`secret file staged: ${f}`);
  }
}

// 2. Obvious credential assignments in staged CONTENT (env-style; avoids false-positives
//    on BLS test vectors which are not KEY=... assignments).
const diff = execSync("git diff --cached -U0", { encoding: "utf8" });
const CRED =
  /^\+.*\b(PRIVATE_KEY\w*|MNEMONIC|SECRET\w*|[A-Z_]*API_KEY|[A-Z_]*TOKEN)\b\s*[:=]\s*["']?(0x[a-fA-F0-9]{40,}|[A-Za-z0-9_\-]{24,})/m;
for (const line of diff.split("\n")) {
  if (!line.startsWith("+") || line.startsWith("+++")) continue;
  if (CRED.test(line) && !/example|sample|placeholder|your_|<|xxxx|0x0+$/i.test(line)) {
    problems.push(`possible credential in staged content: ${line.trim().slice(0, 70)}…`);
  }
}

if (problems.length) {
  console.error("\n✖ commit blocked — possible secret(s) staged:\n");
  for (const p of problems) console.error("  • " + p);
  console.error(
    "\nIf this is a false positive, commit with --no-verify (and double-check it really is safe).\n"
  );
  process.exit(1);
}
