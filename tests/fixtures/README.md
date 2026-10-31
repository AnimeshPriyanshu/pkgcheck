# Test Fixtures for pkgcheck

This directory documents the sample test packages used to validate `pkgcheck` detection rules and end-to-end comparison workflows.

## Fixture Structure

The fixtures are located under `tests/fixtures/`:

- `tests/fixtures/clean/`:
  - `source/`: Legitimate GitHub source repository files (`package.json`, `index.js`, `README.md`).
  - `package/`: Published npm package files (identical to source).
- `tests/fixtures/poisoned/`:
  - `source/`: Clean GitHub source repository files (`package.json`, `index.js`).
  - `package/`: Published npm package files containing hidden supply-chain tamper indicators (`package.json`, `setup.js`).

## Differences Between Clean and Poisoned

- **Clean**:
  The published package perfectly matches the source repository. Every file exists in both directories with identical contents and metadata. No install scripts exist.

- **Poisoned**:
  The published package diverges from the source repository in two key ways that simulate an npm supply-chain tamper:
  1. An unexpected lifecycle script in `package.json`.
  2. An unexpected file in the package payload.

## Expected Suspicious Signals in Poisoned Fixture

1. **Install Lifecycle Script (`install-script`)**:
   - `package/package.json` introduces `"scripts": { "postinstall": "node setup.js" }`, which is completely absent from `source/package.json`.
   - The command is harmless test output, but triggers `pkgcheck/rules.py::check_install_scripts()`.
   - Expected Finding: `file="package.json"`, `status=Status.SUSPICIOUS`, `reason="install-script"`.

2. **Unknown File (`unknown-file`)**:
   - `package/setup.js` exists only in the published package payload, not in `source/`.
   - Triggers `pkgcheck/compare.py::match_files()` and is enriched by `pkgcheck/rules.py::check_unknown_files()`.
   - Expected Finding: `file="setup.js"`, `status=Status.SUSPICIOUS`, `reason="unknown-file"`, with snippet populated from `setup.js`.

## Mapping to Rules Pipeline

| Rule Function | Clean Fixture Result | Poisoned Fixture Result |
| :--- | :--- | :--- |
| `compare.py::match_files` | All files `Status.EXPECTED` (`matched`) | `setup.js` flagged as `Status.SUSPICIOUS` (`unknown-file`) |
| `rules.py::check_install_scripts` | `package.json` remains `Status.EXPECTED` (`matched`) | `package.json` flagged as `Status.SUSPICIOUS` (`install-script`) |
| `rules.py::check_unknown_files` | No unknown files to enrich | `setup.js` snippet populated with first 200 characters |
| `rules.py::apply_rules` | Zero suspicious findings | Two suspicious findings (`package.json`, `setup.js`) |
