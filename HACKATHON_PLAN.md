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

## 2. Work Split (4 People, 6 Core Files + Tests)

| Person | Owns (code) | Owns (tests) | Also Does |
|--------|-------------|--------------|-----------|
| **A** | `models.py`, `compare.py` | `tests/test_models.py`, `tests/test_compare.py` | CI config |
| **B** | `rules.py` | `tests/test_rules.py` | Fixtures (poisoned package) |
| **C** | `explain.py`, `report.py` | `tests/test_explain.py`, `tests/test_report.py` | Demo script, examples/ folder |
| **D** | `cli.py`, `__main__.py`, `README.md` | `tests/test_cli.py` | PR templates, license, submission |

**Why this split:**
- A creates `models.py` first (shared contract), then `compare.py` — both in separate PRs.
- B writes `rules.py` in **one rule per PR** after `compare.py` merges (depends on Finding shape).
- C starts `explain.py` with mocked tests after `models.py` merges, then `report.py`.
- D does `README.md` early, then `__main__.py`, then `cli.py` wiring once compare/rules/report are merged.
- **No `fetch.py`** — cut per fallback plan. No stub files committed.
- Everyone writes tests in the same PR as their module. `__init__.py` stays minimal (version only).

---

## 3. Milestone Table

| ID | Owner | Branch | PR Title | Delivers | Depends On | Definition of Done | Time Window |
|----|-------|--------|----------|----------|------------|-------------------|-------------|
| M0 | All | — | — | Repo init, CI, PR template, smoke test | — | CI green, `pytest` passes, `pkgcheck` prints version | 6:30–7:00 PM (30 min) |
| M1 | A | `feat/shared-models` | Shared: models.py with Finding, Status | `models.py` with Finding(explanation), Status enum | M0 | Tests pass; exported from pkgcheck | 1:07–1:30 AM (23 min) |
| M2 | A | `feat/compare-file-listing` | Compare: list files in package vs source | `compare.py: list_package_files, list_source_files, match_files → list[Finding]` | M1 | Unit tests for listing/matching; list_source_files ignores .git only | 1:30–2:30 AM (60 min) |
| M3 | C | `feat/explain-gemma` | Explain: Gemma via LM Studio for suspicious findings | `explain.py: explain_findings(findings) → list[Finding]` adds .explanation | M1 (Finding shape) | Tests with mocked LM Studio; graceful fallback if unreachable | 1:30–2:30 AM (60 min, parallel with M2) |
| M4 | C | `feat/report-output` | Report: table, JSON, exit code | `report.py: render(findings, format) → str` + exit_code_for_findings | M1 | Tests for table/JSON; exit 1 if any SUSPICIOUS | 2:30–3:15 AM (45 min) |
| M5 | B | `feat/rule-install-scripts` | Rule: install scripts (preinstall/install/postinstall) | `rules.py: apply_rules` — install-script on matched package.json | M2 (compare) | Test: detects added/changed hooks in package.json | 2:30–3:15 AM (45 min) |
| M6 | B | `feat/rule-unknown-files` | Rule: unknown files in package | `rules.py: apply_rules` — unknown-file stays SUSPICIOUS | M2 | Test: poisoned fixture unknown.txt flagged | 3:15–3:45 AM (30 min) |
| M7 | B | `feat/rule-obfuscation` | Rule: obfuscation detection | `rules.py: apply_rules` — huge lines, \x escapes, eval() | M2 | Test: poisoned fixture obfuscated.js flagged | 3:45–4:15 AM (30 min) |
| M8 | B | `feat/rule-build-output` | Rule: build output matched with source = Expected | `rules.py: apply_rules` — build-output only if source match + not obfuscated | M2 | Test: dist/file.min.js with source = Expected | 4:15–4:45 AM (30 min) |
| M9 | D | `feat/cli-wiring` | CLI: wire all modules, add flags | `cli.py: main(args)` calls compare→rules→explain→report | M2, M3, M4, M5-M8 | Smoke test runs full pipeline on fixtures; `--json` flag works | 4:45–5:15 AM (30 min) |
| M10 | D | `feat/readme-main` | README + __main__.py entry point | `README.md` with usage; `__main__.py` calls cli.main | M0 | `python -m pkgcheck` works; README renders | 1:30–2:00 AM (30 min, parallel) |
| M11 | All | `chore/examples-and-docs` | Examples folder, final HACKATHON.md | `examples/` with real output; updated HACKATHON.md | M9 | `examples/` committed; HACKATHON.md matches rubric | 5:15–5:45 AM (30 min) |
| M12 | All | `chore/polish-and-demo` | Polish, demo rehearsal, submission | No secrets, license, CI green, OrganizerHQ submitted | M11 | All checks pass; demo runs in < 2 min | 5:45–6:15 AM (30 min) |
| — | — | — | **FEATURE FREEZE** | No new features after 5:00 AM | — | Only bug fixes, docs, README | 5:00 AM |
| — | — | — | **FINAL MERGE DEADLINE** | Last PR merged by 6:30 AM | — | CI green on main | 6:30 AM |

---

## 4. Critical Path

```
M0 (init) → M1 (shared-models)
                ↓
         M2 (compare) + M3 (explain) [PARALLEL]
                ↓              ↓
         M4 (report) ← needs M1
                ↓
    M5→M6→M7→M8 (rules, sequential) ← needs M2
                ↓
         M9 (cli-wiring) ← needs M2,M3,M4,M5-M8
                ↓
         M10 (README/__main__) + M11 (examples) [PARALLEL]
                ↓
         M12 (polish) → DONE
```

**What each person does while waiting:**

| Person | While Waiting For… | Does This Instead |
|--------|-------------------|-------------------|
| A | — | M1 first, then M2 immediately |
| B | M2 (compare) | Build poisoned fixtures, write rule test skeletons offline |
| C | M1 (models) | M3 (explain) starts immediately after M1 merges; M4 after |
| D | M2,M3,M4,M5-M8 | M10 (README/__main__) early; prep cli wiring skeleton |

---

## 5. Timeline (Current: 1:07 AM, ~5.5 hrs left)

| Time | Activity |
|------|----------|
| **1:07–1:30 AM** | **M1**: A creates `feat/shared-models` (models.py + tests). All review. |
| **1:30–2:30 AM** | **M2 + M3 parallel**: A on `feat/compare-file-listing`; C on `feat/explain-gemma`. |
| **1:30–2:00 AM** | **M10 parallel**: D on `feat/readme-main` (README + `__main__.py`). |
| **2:30–3:15 AM** | **M4 + M5 parallel**: C on `feat/report-output`; B on `feat/rule-install-scripts`. |
| **3:15–4:45 AM** | **M6→M7→M8 sequential**: B does 3 rule PRs (unknown-files, obfuscation, build-output). |
| **4:45–5:15 AM** | **M9**: D wires CLI (`feat/cli-wiring`) once all deps merged. |
| **5:15–5:45 AM** | **M11**: All create `examples/`, finalize HACKATHON.md. |
| **5:45–6:15 AM** | **M12**: Final polish, demo rehearsal, OrganizerHQ submission. |
| **6:15–6:30 AM** | **Buffer**: Last CI checks, merge final PRs. |
| **6:30 AM** | **Hackathon ends** — last merge must be in. |
| **8:30 AM** | **Presentations + Q&A** — any member can be asked about any file. |

---

## 6. Cross-Review Pairs

| Reviewer | Reviews |
|----------|---------|
| A | B's rule PRs, D's CLI/README PRs |
| B | A's compare PR, C's explain/report PRs |
| C | D's CLI/README PRs, A's compare PR |
| D | C's explain/report PRs, B's rule PRs |

**Rule:** Self-merge only if no one else is available. Ping in Discord/Slack for review.

---

## 7. Learning Task Per Person (So Everyone Can Explain Everything)

| Person | Must Be Able to Explain |
|--------|-------------------------|
| A | How `models.py` defines Finding/Status; how `compare.py` produces findings |
| B | Each rule: install-scripts (json diff), unknown-files, obfuscation (heuristics), build-output (source match + not obfuscated) |
| C | How Gemma is called via LM Studio, fallback to reason, how report formats table/JSON + exit code |
| D | Full CLI flow: args → compare → rules → explain → report → exit code; README usage |

**Practice:** 15-min pair walkthroughs after each milestone merges.

---

## 8. Fallback Plan (If Behind)

| Priority | Cut First |
|----------|-----------|
| 1 (keep) | Core compare + rules (install-script + unknown-file) + CLI + report (exit code works) |
| 2 (keep) | Gemma explain for suspicious items (mock in demo if LM Studio fails) |
| 3 (cut) | Obfuscation rule, build-output rule, JSON output — keep table only |
| 4 (cut) | `examples/` folder — show live demo output instead |
| 5 (cut) | README polish — keep minimal usage in `--help` |

**Minimum viable demo:** `pkgcheck --package fixtures/package/poisoned --source fixtures/source` → prints table with ≥1 SUSPICIOUS → exits 1.

---

## 9. Final Checklist Before 6:30 AM

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

## Quick Reference: Branch Naming

```
feat/<short-description>    # new feature
fix/<short-description>     # bug fix
test/<short-description>    # test only
chore/<short-description>   # docs, config, CI
docs/<short-description>    # documentation updates
```

Example: `feat/shared-models`, `feat/rule-install-scripts`, `docs/hackathon-plan-fix`

---

## Communication

- **Discord/Slack channel** for instant sync
- **PR comments** for code review
- **Standups** at: 1:30 AM, 2:30 AM, 3:30 AM, 4:30 AM, 5:30 AM (5 min each)
- **Blockers** called out immediately in channel — unblock in < 10 min or escalate

---

*Plan version 2.0 — updated at 1:07 AM per team sync.*