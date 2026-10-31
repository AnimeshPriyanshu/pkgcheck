# pkgcheck Hackathon Plan (12 hours: 6:30 PM – 6:30 AM)

---

## 1. Shared Contract: Data Shape Between Modules

All modules pass a **list of `Finding` objects**. This is the single source of truth.

```python
# pkgcheck/models.py  (created first, imported by everyone)
from dataclasses import dataclass
from enum import Enum

class Status(Enum):
    EXPECTED = "Expected"
    SUSPICIOUS = "Suspicious"

@dataclass
class Finding:
    file: str                    # relative path, e.g. "package.json"
    status: Status               # EXPECTED or SUSPICIOUS
    reason: str                  # short rule name, e.g. "install-script", "unknown-file"
    snippet: str | None = None   # first 200 chars of diff or file content
    line: int | None = None      # line number if applicable
    explanation: str | None = None  # added by explain.py for SUSPICIOUS findings
```

**Flow:**
```
compare.py → list[Finding]
      ↓
rules.py  → enriches each Finding with status + reason
      ↓
explain.py → adds .explanation (str) to SUSPICIOUS only
      ↓
report.py  → prints table / JSON, returns exit code
```

---

## 2. ROLES

| Code | Name | Owns | Cross-reviews |
|------|------|------|---------------|
| **A** | Ani | `models.py`, `compare.py` | B |
| **B** | Ris | `fixtures/`, `rules.py` (one rule per PR) | A |
| **C** | NA | `explain.py`, `report.py` | D |
| **D** | PV | `README.md`, `__main__.py`, `cli.py` | C |

**Pairs:** A↔B, C↔D. Each PR reviewed by the partner.

---

## 3. WAVES AND TASK BOARD

| ID | Wave | Owner | Branch | Delivers | Depends on | Status |
|----|------|-------|--------|----------|------------|--------|
| W1-A1 | 1 | A | `feat/shared-models` | `models.py` (Status, Finding with explanation) + tests | — | not started |
| W1-A2 | 1 | A | `docs/hackathon-plan-fix` | Plan corrections | — | in progress |
| W1-B1 | 1 | B | `test/fixtures` | Clean + poisoned fixtures (harmless) + `tests/fixtures/README.md` | — | not started |
| W1-D1 | 1 | D | `docs/readme` | `README.md` | — | not started |
| W1-D2 | 1 | D | `feat/main-module` | `__main__.py` + subprocess test | — | not started |
| W1-C0 | 1 | C | *(no PR)* | LM Studio running `google/gemma-4-e4b`, local server tested | — | not started |
| W2-A3 | 2 | A | `feat/compare-file-listing` | `compare.py` + tests | W1-A1 | not started |
| W2-C1 | 2 | C | `feat/explain-gemma` | `explain.py` with mocked test + fallback | W1-A1 | not started |
| W3-B2 | 3 | B | `feat/rule-install-scripts` | Install-script rule (json diff on matched package.json) | W2-A3, W1-B1 | not started |
| W3-B3 | 3 | B | `feat/rule-unknown-files` | Unknown-file rule | W3-B2 | not started |
| W3-B4 | 3 | B | `feat/rule-obfuscation` | Obfuscation rule (huge lines, \x escapes, eval) | W3-B2 | not started |
| W3-B5 | 3 | B | `feat/rule-build-output` | Build-output rule (source match + not obfuscated) | W3-B2 | not started |
| W3-C2 | 3 | C | `feat/report-output` | Table, JSON, exit code 0/1 | W1-A1 | not started |
| W4-D3 | 4 | D | `feat/cli-wiring` | CLI wiring: compare→rules→explain→report, `--json` flag | W2-A3, W3-B2, W3-C2 (explain if W2-C1 merged) | not started |
| W5-ALL | 5 | All | `docs/examples-output` | Real output on both fixtures, demo rehearsal, blog post | W4-D3 | not started |

---

## 4. WHEN YOU FINISH A TASK

Rules every person follows:
- Ani updates the board. After your PR merges, message Ani. Ani ticks rows in a small docs/board-update PR about once an hour. Do not edit the board in your feature PR.
- Run `git checkout main && git pull` before starting every new branch.
- Tests go in the same PR as the code.
- The PR description names the **models used** (`google/gemma-4-e4b` via LM Studio) and the **AI coding assistant** (opencode / nemotron-3-ultra).

---

## 5. TIME AND CUT LIST

- **Feature freeze:** 90 minutes before 6:30 AM (5:00 AM).
- **Last merge:** 6:30 AM sharp.
- **Cut order if short on time:**
  1. JSON output (keep table only)
  2. Obfuscation rule
  3. Build-output rule
- **Never cut:** compare, install-scripts rule, unknown-files rule, table report, exit code, CLI, `examples/`, `README.md`.
- `fetch.py` is cut — no stub files committed.

---

## 6. Learning Task Per Person (So Everyone Can Explain Everything)

| Person | Must Be Able to Explain |
|--------|-------------------------|
| A (Ani) | How `models.py` defines Finding/Status; how `compare.py` produces findings |
| B (Ris) | Each rule: install-scripts (json diff), unknown-files, obfuscation (heuristics), build-output (source match + not obfuscated) |
| C (NA) | How Gemma is called via LM Studio, fallback to reason, how report formats table/JSON + exit code |
| D (PV) | Full CLI flow: args → compare → rules → explain → report → exit code; README usage |

**Practice:** 15-min pair walkthroughs after each milestone merges.

---

## 7. Fallback Plan (If Behind)

| Priority | Cut First |
|----------|-----------|
| 1 (keep) | Core compare + rules (install-script + unknown-file) + CLI + report (exit code works) |
| 2 (keep) | Gemma explain for suspicious items (mock in demo if LM Studio fails) |
| 3 (cut) | Obfuscation rule, build-output rule, JSON output — keep table only |
| 4 (cut) | `examples/` folder — show live demo output instead |
| 5 (cut) | README polish — keep minimal usage in `--help` |

**Minimum viable demo:** `pkgcheck --package fixtures/package/poisoned --source fixtures/source` → prints table with ≥1 SUSPICIOUS → exits 1.

---

## 8. Final Checklist Before 6:30 AM

- [ ] CI green on `main` (both workflows pass)
- [ ] `HACKATHON.md` exists with: problem statement, models used (google/gemma-4-e4b via LM Studio), AI assistant (opencode/nemotron-3-ultra), team, demo instructions
- [ ] `examples/` folder with real terminal output (at least 2 runs: clean + suspicious)
- [ ] No secrets in repo (check `.env`, API keys, tokens)
- [ ] LICENSE file (MIT or Apache-2.0)
- [ ] OrganizerHQ submission complete with repo link
- [ ] `pytest` passes locally
- [ ] `pkgcheck --help` works; `python -m pkgcheck` works
- [ ] Demo runs in < 2 minutes on a fresh clone
- [ ] Every team member can run the demo and explain one module
- [ ] No stub files committed (`fetch.py` removed/not added)
- [ ] `__init__.py` minimal (version only)
- [ ] Every PR template names model and AI assistant used

---

## 9. Quick Reference: Branch Naming

```
feat/<short-description>    # new feature
fix/<short-description>     # bug fix
test/<short-description>    # test only
chore/<short-description>   # docs, config, CI
docs/<short-description>    # documentation updates
```

Example: `feat/shared-models`, `feat/rule-install-scripts`, `docs/hackathon-plan-fix`

---

## 10. Communication

- **Discord/Slack channel** for instant sync
- **PR comments** for code review
- **Standups** at: 1:30 AM, 2:30 AM, 3:30 AM, 4:30 AM, 5:30 AM (5 min each)
- **Blockers** called out immediately in channel — unblock in < 10 min or escalate

---

*Plan version 3.0 — updated with roles, waves, task board, and cut list.*