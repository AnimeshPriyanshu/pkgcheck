# pkgcheck

Deterministic comparison engine and optional AI security explainer for npm packages vs. source repositories.

---

## Overview

`pkgcheck` is a security tool designed to detect discrepancies between a published npm package and its corresponding source repository. By performing deterministic file-level matching and analyzing package contents with specialized heuristic rules, `pkgcheck` identifies potential supply-chain tampering before untrusted code runs in production or developer environments.

The tool compares two local directories:
1. The **package directory** (e.g., an unpacked `.tgz` release payload from the npm registry).
2. The **source directory** (e.g., a checkout of the repository at the matching Git tag).

---

## Problem

In software supply-chain attacks, adversaries rarely compromise public source code directly. Instead, they may exploit compromised maintainer credentials, insecure build pipelines, or publish automation to alter the artifact published to the registry.

Common attack patterns include:
- Injecting malicious install lifecycle hooks (`preinstall`, `postinstall`) absent in source.
- Shipping extra payload files that do not exist in the source repository.
- Bundling obfuscated code to conceal execution of malware.
- Introducing untracked build artifacts that hide unauthorized modifications.

`pkgcheck` exposes these discrepancies deterministically by comparing the published artifact against the source tree.

---

## How It Works

`pkgcheck` operates on two local directories through a sequential, modular pipeline:

```text
Package Directory + Source Directory
                ↓
             Compare
        (File Matching)
                ↓
              Rules
    (Deterministic Analysis)
                ↓
       Optional Explain
     (Local Google Gemma)
                ↓
             Report
         (Table / JSON)
```

1. **Compare (`pkgcheck.compare`)**: Lists files in both directories (excluding internal `.git` metadata) and groups them into `matched`, `unknown-file` (present in package only), and `missing-in-package` (present in source only).
2. **Rules (`pkgcheck.rules`)**: Applies deterministic security rules to enrich findings with severity `Status.EXPECTED` or `Status.SUSPICIOUS`.
3. **Optional Explain (`pkgcheck.explain`)**: When enabled via `--explain`, queries a local Google Gemma model to generate concise security explanations for suspicious findings.
4. **Report (`pkgcheck.report`)**: Formats findings as an aligned terminal table or structured JSON and computes the process exit code.

---

## Key Features

- **Zero Runtime Dependencies**: Built entirely using the Python standard library. No external pip dependencies are required to run the CLI.
- **Deterministic Detection**: Evaluates packages against four precise rule sets rather than probabilistic heuristics.
- **Optional Local AI Explanations**: Supports local inference via Google Gemma (`google/gemma-4-e4b`) in LM Studio with deterministic fallback if the model server is offline.
- **Multiple Output Formats**: Human-readable aligned terminal tables for developers and formatted JSON output for automation.
- **Standardized Exit Codes**: Predictable exit codes (`0`, `1`, `2`) for clean integration into CI/CD pipelines and auditing workflows.

---

## Detection Rules

`pkgcheck` executes four deterministic rules in order:

### 1. Install Scripts (`install-script`)
Inspects matched `package.json` files for lifecycle install scripts:
- Monitored scripts: `preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, and `postprepare`.
- Flags scripts that were newly added to the package or modified compared to the source repository.

### 2. Unknown Files (`unknown-file`)
Detects files present in the published package payload that do not exist in the source repository. For each unexpected file, `pkgcheck` captures the first 200 characters as a preview snippet.

### 3. Obfuscation (`obfuscation`)
Analyzes JavaScript and TypeScript files (`.js`, `.mjs`, `.cjs`, `.ts`) in the package for suspicious patterns:
- Lines exceeding 500 characters in length.
- Lines containing 3 or more hexadecimal escape sequences (`\xNN`).
- Direct invocations of `eval()`.

### 4. Build Output Reclassification (`build-output`)
Safely reclassifies legitimate compiled artifacts:
- Recognized directories: `dist/`.
- Recognized artifact extensions: `.min.js`, `.min.css`, `.d.ts`, `.map`.
- Matches artifacts against source files (`.ts`, `.js`, `.tsx`, `.jsx`, `.css`) located under `src/` or the repository root.
- Reclassifies matching non-malicious artifacts from `Suspicious` to `Expected` (`build-output`), while preserving `Suspicious` status if dangerous obfuscation (`eval()` or $\ge 3$ hex escapes) is present.

---

## Installation

### Prerequisites
- Python >= 3.10

### Setup

```bash
# Clone the repository
git clone https://github.com/AnimeshPriyanshu/pkgcheck.git
cd pkgcheck

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# Install pkgcheck in editable mode
pip install -e .
```

To install development dependencies (for running tests):

```bash
pip install -e ".[dev]"
```

---

## CLI Usage

Run `pkgcheck` directly or via Python's module runner:

```bash
pkgcheck -p <PACKAGE_DIR> -s <SOURCE_DIR>
# or
python -m pkgcheck -p <PACKAGE_DIR> -s <SOURCE_DIR>
```

### Options

| Flag | Argument | Description |
|---|---|---|
| `-p`, `--package` | `PATH` | Path to the unpacked npm package directory (required) |
| `-s`, `--source` | `PATH` | Path to the source repository directory (required) |
| `--json` | None | Output findings as a structured JSON array instead of a table |
| `--explain` | None | Generate AI security explanations for suspicious findings using local Gemma |
| `-v`, `--version` | None | Display program version and exit |
| `-h`, `--help` | None | Show help message and exit |

---

## Exit Codes

| Exit Code | Meaning | Details |
|:---:|---|---|
| `0` | Clean | All findings have status `Expected` (no suspicious differences found) |
| `1` | Suspicious | One or more findings have status `Suspicious` (supply-chain indicators present) |
| `2` | Error | Invalid CLI arguments, or `--package`/`--source` directory does not exist |

---

## Examples

The repository includes sample fixtures under `tests/fixtures/` representing clean and tampered packages.

### 1. Clean Package (Table Output)

```bash
pkgcheck --package tests/fixtures/clean/package --source tests/fixtures/clean/source
```

Output:
```text
STATUS   | REASON  | FILE         | SNIPPET
---------+---------+--------------+--------
Expected | matched | README.md    |
Expected | matched | index.js     |
Expected | matched | package.json |
```
*Process exit code: `0`*

### 2. Poisoned Package (Table Output)

```bash
pkgcheck --package tests/fixtures/poisoned/package --source tests/fixtures/poisoned/source
```

Output:
```text
STATUS     | REASON             | FILE         | SNIPPET
-----------+--------------------+--------------+---------------------------------------------------
Expected   | missing-in-package | index.js     |
Suspicious | install-script     | package.json | "postinstall": "node setup.js"
Suspicious | unknown-file       | setup.js     | /**
 * Harmless fixture setup script simulating...
```
*Process exit code: `1`*

### 3. JSON Output (`--json`)

```bash
pkgcheck --package tests/fixtures/poisoned/package --source tests/fixtures/poisoned/source --json
```

Output:
```json
[
  {
    "file": "index.js",
    "status": "Expected",
    "reason": "missing-in-package"
  },
  {
    "file": "package.json",
    "status": "Suspicious",
    "reason": "install-script",
    "snippet": "\"postinstall\": \"node setup.js\""
  },
  {
    "file": "setup.js",
    "status": "Suspicious",
    "reason": "unknown-file",
    "snippet": "/**\n * Harmless fixture setup script simulating an unexpected package file.\n * Used for testing pkgcheck unknown-file detection.\n */\nconsole.log(\"pkgcheck test fixture: harmless setup script executed\""
  }
]
```

### 4. Optional AI Explanations (`--explain`)

```bash
pkgcheck --package tests/fixtures/poisoned/package --source tests/fixtures/poisoned/source --explain --json
```

Output:
```json
[
  {
    "file": "index.js",
    "status": "Expected",
    "reason": "missing-in-package",
    "explanation": ""
  },
  {
    "file": "package.json",
    "status": "Suspicious",
    "reason": "install-script",
    "snippet": "\"postinstall\": \"node setup.js\"",
    "explanation": "The package.json contains an install lifecycle script (preinstall, install, or postinstall) that is not present in the source repository. Attackers often use these scripts to execute malicious code during package installation."
  },
  {
    "file": "setup.js",
    "status": "Suspicious",
    "reason": "unknown-file",
    "snippet": "/**\n * Harmless fixture setup script simulating an unexpected package file.\n * Used for testing pkgcheck unknown-file detection.\n */\nconsole.log(\"pkgcheck test fixture: harmless setup script executed\"",
    "explanation": "A file exists in the published package but not in the source repository. This could indicate that malicious files were added during the publishing process or that the package was tampered with."
  }
]
```

---

## Local AI Setup (`--explain`)

The `--explain` flag enhances findings with security analysis powered by **Google Gemma** (`google/gemma-4-e4b`) running locally through LM Studio.

### LM Studio Configuration

1. Install [LM Studio](https://lmstudio.ai/).
2. Download `google/gemma-4-e4b`.
3. Start the local inference server (default endpoint: `http://127.0.0.1:1234/v1`).

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `LM_STUDIO_URL` | `http://127.0.0.1:1234/v1` | Base URL of OpenAI-compatible chat completions API |
| `GEMMA_MODEL` | `google/gemma-4-e4b` | Model name identifier sent in request payload |

### Offline Fallback
LM Studio is completely optional. If LM Studio is not running, times out, or returns an error, `pkgcheck` gracefully falls back to deterministic rule explanations and continues without failure.

---

## Development & Testing

Run the test suite using `pytest`:

```bash
pytest -v
```

The test suite contains 122 automated unit and integration tests across:
- Data models (`test_models.py`)
- File comparison and Git metadata filtering (`test_compare.py`)
- Detection rules (`test_rules.py`)
- AI explanation and fallback handling (`test_explain.py`)
- Table formatting and JSON rendering (`test_report.py`)
- CLI options, exit codes, and subprocess execution (`test_cli.py`)
- Test fixtures validation (`test_fixtures.py`)
- Smoke tests (`test_smoke.py`)

---

## Project Structure

```text
pkgcheck/
├── pkgcheck/
│   ├── __init__.py        # Version definition (0.1.0)
│   ├── __main__.py        # Executable entrypoint (python -m pkgcheck)
│   ├── cli.py             # CLI parser and pipeline orchestration
│   ├── compare.py         # Directory traversal and set matching
│   ├── explain.py         # Gemma / LM Studio client and fallback explanations
│   ├── models.py          # Shared Finding and Status dataclasses
│   ├── report.py          # Table and JSON report formatting, exit code logic
│   └── rules.py           # 4 detection rules (scripts, unknown, obfuscation, build)
├── scripts/
│   └── check_pr_models.py # CI validation for pull request metadata
├── tests/
│   ├── fixtures/
│   │   ├── clean/         # Sample matching package and source
│   │   └── poisoned/      # Sample package with install script and extra file
│   ├── test_cli.py        # CLI argument and execution tests
│   ├── test_compare.py    # Comparison unit tests
│   ├── test_explain.py    # AI explanation unit and mock tests
│   ├── test_fixtures.py   # Fixture integrity tests
│   ├── test_models.py     # Data model tests
│   ├── test_report.py     # Report rendering tests
│   ├── test_rules.py      # Rule heuristic tests
│   └── test_smoke.py      # Smoke test
├── LICENSE                # MIT License
└── pyproject.toml         # Packaging metadata and test config
```

---

## Current Scope & Limitations

- **Local Directory Comparison**: `pkgcheck` currently compares two local filesystem directories. Unpacking an npm tarball (`tar -xzf <package>.tgz`) or cloning a GitHub repository must be performed prior to running `pkgcheck`.
- **Automatic Fetching**: Direct remote downloading from the npm registry or GitHub APIs is not currently built into the CLI.
- **Optional AI Requirement**: The core rule engine runs locally with zero network calls; local AI via LM Studio is strictly opt-in via `--explain`.

---

## License

This project is licensed under the MIT License. See the [LICENSE](file:///Users/rishabh/Desktop/pkgcheck/LICENSE) file for details.
