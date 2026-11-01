# pkgcheck 2-Minute Demo Script

**Target time:** ~2 minutes  
**Audience:** Hackathon judges and developers  
**Goal:** Show that pkgcheck detects supply-chain tampering in npm packages

---

## Setup (before demo)

```bash
# 1. Clone and install (30 seconds)
git clone <repo-url>
cd pkgcheck
pip install -e ".[dev]"

# 2. Optional: Start LM Studio for live AI explanations
#    Model: google/gemma-4-e4b at http://127.0.0.1:1234/v1
#    (Demo works without it — fallback explanations are built in)
```

---

## Demo Flow (2 minutes)

### 1. Hook (10 seconds)
> "pkgcheck answers one question: **Does the published npm package match its GitHub source?**  
> It compares the package payload against the source repo, detects tampering, and explains *why* it's suspicious."

**Show the help:**
```bash
python -m pkgcheck --help
```

---

### 2. Clean Package — Baseline (30 seconds)
> "First, a clean package — no tampering. Every file matches."

```bash
python -m pkgcheck \
  -p tests/fixtures/clean/package \
  -s tests/fixtures/clean/source
```

**Expected output:**
```
STATUS   | REASON  | FILE         | SNIPPET
---------+---------+--------------+--------
Expected | matched | README.md    |        
Expected | matched | index.js     |        
Expected | matched | package.json |
```
> "All findings are **Expected**. Exit code is **0** — CI passes."

**Show exit code:**
```bash
echo $?
# 0
```

---

### 3. Poisoned Package — The Reveal (50 seconds)
> "Now a poisoned package — simulates an npm supply-chain attack.  
> Two tamper indicators: an unexpected `postinstall` script, and a file `setup.js` that doesn't exist in the source."

```bash
python -m pkgcheck \
  -p tests/fixtures/poisoned/package \
  -s tests/fixtures/poisoned/source
```

**Expected output:**
```
STATUS     | REASON             | FILE         | SNIPPET                                           
-----------+--------------------+--------------+---------------------------------------------------
Expected   | missing-in-package | index.js     |                                                   
Suspicious | install-script     | package.json | "postinstall": "node setup.js"                    
Suspicious | unknown-file       | setup.js     | /**
 * Harmless fixture setup script simulating...
```

> "Two **Suspicious** findings:
> 1. **install-script** — `postinstall` runs `node setup.js` during `npm install`. Attackers use this to execute code on install.
> 2. **unknown-file** — `setup.js` exists only in the published package, not in GitHub."

**Show exit code:**
```bash
echo $?
# 1 — CI blocks the release
```

---

### 4. JSON Output for Automation (15 seconds)
> "JSON output for CI/CD pipelines and tooling."

```bash
python -m pkgcheck \
  -p tests/fixtures/poisoned/package \
  -s tests/fixtures/poisoned/source \
  --json
```

**Key point:** "Structured data with all fields — file, status, reason, snippet. Easy to parse, alert on, or feed into dashboards."

---

### 5. AI Explanations — Security Context (15 seconds)
> "Security teams need to know *why* it's suspicious. pkgcheck uses local Gemma via LM Studio to explain findings in plain English. Works offline, no data leaves your machine."

```bash
python -m pkgcheck \
  -p tests/fixtures/poisoned/package \
  -s tests/fixtures/poisoned/source \
  --json --explain
```

**Expected output (fallback mode — LM Studio offline):**
```json
{
  "file": "package.json",
  "status": "Suspicious",
  "reason": "install-script",
  "explanation": "The package.json contains an install lifecycle script... Attackers often use these scripts to execute malicious code during package installation."
}
```

> "If LM Studio is running, you get the AI explanation. If not, you still get a deterministic, security-focused fallback. **Never crashes, always explains.**"

---

### 6. Closing (10 seconds)
> "pkgcheck: compare, detect, explain, block.  
> One command in your CI pipeline prevents poisoned packages from reaching users."

**Show the repo:**
```bash
ls pkgcheck/
# models.py  compare.py  rules.py  explain.py  report.py  cli.py
```

---

## Talking Points for Q&A

| Question | Answer |
|----------|--------|
| "How does it detect obfuscation?" | Heuristics: lines > 500 chars, ≥3 hex escapes (`\xXX`), `eval()` calls. Only on JS/TS files. |
| "What if LM Studio is down?" | Built-in deterministic fallbacks for all 7 rule types. Zero dependency on external APIs. |
| "Can it run in GitHub Actions?" | Yes — `pip install -e . && python -m pkgcheck -p pkg -s src`. Exit code 1 fails the job. |
| "What about false positives?" | Build artifacts (`.min.js`, `.d.ts`) with matching source are auto-classified as `build-output` (Expected). |
| "Why not just `npm audit`?" | `npm audit` checks known vulnerabilities in dependencies. pkgcheck checks **your package vs. your source** — supply-chain integrity, not dependency CVEs. |
| "Does it execute package code?" | **Never.** Static analysis only — reads files, compares, explains. |

---

## Fallback Commands (if something breaks)

| Scenario | Command |
|----------|---------|
| LM Studio not running | `--explain` still works (fallback) |
| Need only table | Omit `--json` |
| Need only exit code | `pkgcheck ...; echo $?` |
| Test different fixture | Swap `-p` and `-s` paths |

---

## Time Check

| Segment | Target | Actual |
|---------|--------|--------|
| Hook + help | 0:10 | |
| Clean package | 0:40 | |
| Poisoned package | 1:30 | |
| JSON output | 1:45 | |
| AI explanations | 2:00 | |
| Closing | 2:10 | |
| **Total** | **~2 min** | |

---

## Pro Tips

- Run `python -m pkgcheck -p tests/fixtures/clean/package -s tests/fixtures/clean/source --json --explain` first to verify LM Studio connectivity
- Have a terminal ready with the commands pre-typed (use `history` or a script)
- Point at the **exit code** — it's the CI signal
- Emphasize **offline, no cloud, no data exfiltration**