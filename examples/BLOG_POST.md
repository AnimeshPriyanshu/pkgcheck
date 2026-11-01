# pkgcheck: Does the Package Match Its Source?

**Hacktoberfest Hack Day 2026 — Problem 4**  
**Team:** OpenSourcers (Ani, Ris, NA, PV)  
**Model:** `google/gemma-4-e4b` via LM Studio (local, offline)

---

## The Problem

You publish an npm package. A user installs it. But **does the published tarball actually match your GitHub source?**

Supply-chain attacks on npm are real:
- [event-stream](https://github.com/dominictarr/event-stream/issues/116) — malicious code injected in a minor version
- [ua-parser-js](https://github.com/faisalman/ua-parser-js/issues/484) — crypto miner added post-publish
- [coa](https://github.com/veged/coa/issues/129) — password stealer in `postinstall`

These attacks share a pattern: **the published package diverges from the source repository**. The attacker publishes a modified tarball — adding install scripts, obfuscated code, or entirely new files — that never existed in the source repo.

Existing tools don't catch this:
- `npm audit` — checks known CVEs in *dependencies*, not your own package
- `sigstore` / `npm attestations` — verify *provenance*, not *content equivalence*
- Manual diffing — doesn't scale in CI

**pkgcheck closes this gap:** it compares the unpacked package against the source repo at the matching tag, detects every discrepancy, classifies it, and explains *why* it matters.

---

## Our Approach

### Core Philosophy

1. **Static analysis only** — never executes package code
2. **Offline-first** — no cloud APIs, no data leaves your machine
3. **Deterministic rules** — reproducible, auditable, no AI hallucination
4. **AI only for explanations** — Gemma interprets findings, never decides them

### Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  compare.py │────▶│  rules.py   │────▶│  explain.py │────▶│  report.py  │────▶│   CLI / CI  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
    list files        enrich with        add human          render table      exit code
    & match           status/reason      explanations       / JSON / exit      (0 or 1)
```

**Shared contract:** `Finding` dataclass (file, status, reason, snippet, line, explanation)

---

## Detection Rules

| Rule | Trigger | Severity | Rationale |
|------|---------|----------|-----------|
| **install-script** | `preinstall`/`install`/`postinstall` in package.json not in source | Suspicious | Attackers execute code on `npm install` |
| **unknown-file** | File in package but not in source | Suspicious | Hidden payloads, backdoors, data exfiltration |
| **obfuscation** | Lines > 500 chars, ≥3 hex escapes (`\xXX`), `eval()` calls | Suspicious | Hides malicious logic from reviewers |
| **build-output** | Minified/transpiled files with matching source | Expected | Legitimate build artifacts (`.min.js`, `.d.ts`, `.map`) |

**Rule order matters:** `install-script` → `unknown-file` → `obfuscation` → `build-output`  
Later rules can *reclassify* earlier findings (e.g., obfuscated build output stays suspicious).

---

## Gemma Integration

### Why Local Gemma?

- **Zero cloud dependency** — runs on your laptop / CI runner
- **No API keys, no rate limits, no data exfiltration**
- **Model:** `google/gemma-4-e4b` via LM Studio (OpenAI-compatible API)
- **Fallback:** Deterministic explanations for all 7 reason types when LM Studio is unavailable

### Prompt Design

```
You are a security analyst reviewing an npm package for suspicious differences.
File: setup.js
Status: Suspicious
Reason: unknown-file
Snippet: console.log("harmless setup script")

Provide a concise, security-focused explanation (2-3 sentences) of why this finding
is suspicious or expected. Do not include reasoning steps or internal thoughts.
```

**Output:** "A file exists in the published package but not in the source repository. This could indicate that malicious files were added during the publishing process or that the package was tampered with."

### Graceful Fallback

If LM Studio is unreachable, times out, or returns invalid JSON → **instant fallback** to deterministic explanation. No crash, no silent failure, always a useful explanation.

---

## Demo Results

### Clean Package (matches source)
```bash
$ python -m pkgcheck -p tests/fixtures/clean/package -s tests/fixtures/clean/source
STATUS   | REASON  | FILE         | SNIPPET
---------+---------+--------------+--------
Expected | matched | README.md    |        
Expected | matched | index.js     |        
Expected | matched | package.json |
Exit code: 0
```

### Poisoned Package (simulated supply-chain attack)
```bash
$ python -m pkgcheck -p tests/fixtures/poisoned/package -s tests/fixtures/poisoned/source
STATUS     | REASON             | FILE         | SNIPPET
-----------+--------------------+--------------+---------------------------------------------------
Expected   | missing-in-package | index.js     |                                                   
Suspicious | install-script     | package.json | "postinstall": "node setup.js"
Suspicious | unknown-file       | setup.js     | /**
 * Harmless fixture setup script simulating...
Exit code: 1
```

### With AI Explanations (fallback mode)
```bash
$ python -m pkgcheck -p tests/fixtures/poisoned/package -s tests/fixtures/poisoned/source --json --explain
```
```json
{
  "file": "package.json",
  "status": "Suspicious",
  "reason": "install-script",
  "explanation": "The package.json contains an install lifecycle script (preinstall, install, or postinstall) that is not present in the source repository. Attackers often use these scripts to execute malicious code during package installation."
}
```

---

## Limitations & Future Work

| Limitation | Mitigation / Future |
|------------|---------------------|
| **No network fetch** | Stretch goal: `fetch.py` to download .tgz and clone source at tag |
| **No semver/tag matching** | Assumes you provide correct source dir; could auto-resolve tag from package.json version |
| **JS/TS only for obfuscation** | Extend to Python, Go, Rust with language-specific heuristics |
| **No binary analysis** | Cannot detect malicious compiled addons (`.node` files) |
| **Single-threaded** | Could parallelize file scanning for large packages |
| **No config file** | Hardcoded thresholds; could add `.pkgcheckrc` for customization |

---

## Why This Matters

> **"Trust but verify" doesn't scale. pkgcheck automates the verification.**

In 2 minutes, you can add pkgcheck to your CI:
```yaml
# .github/workflows/check-package.yml
- name: Verify package matches source
  run: |
    pip install -e .
    python -m pkgcheck -p ./package -s ./source
```

If exit code is 1, the build fails. The maintainer sees exactly *what* is suspicious and *why*.

No cloud. No secrets. No excuses.

---

## Get Started

```bash
git clone https://github.com/AnimeshPriyanshu/pkgcheck
cd pkgcheck
pip install -e ".[dev]"

# Test clean
python -m pkgcheck -p tests/fixtures/clean/package -s tests/fixtures/clean/source

# Test poisoned
python -m pkgcheck -p tests/fixtures/poisoned/package -s tests/fixtures/poisoned/source

# With AI explanations
python -m pkgcheck -p tests/fixtures/poisoned/package -s tests/fixtures/poisoned/source --json --explain
```

**Repository:** https://github.com/AnimeshPriyanshu/pkgcheck  
**License:** MIT  
**Team:** OpenSourcers (Ani, Ris, NA, PV)