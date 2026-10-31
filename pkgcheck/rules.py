"""Detection rules for pkgcheck."""

import json
from pathlib import Path
import re

from pkgcheck.models import Finding, Status

INSTALL_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
}

JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts"}
HUGE_LINE_THRESHOLD = 500
HEX_ESCAPE_PATTERN = re.compile(r"\\x[0-9a-fA-F]{2}")
EVAL_PATTERN = re.compile(r"\beval\s*\(")


def _load_json(file_path: Path) -> dict | None:
    """Safely load and parse a JSON file, returning None if missing or invalid."""
    if not file_path.is_file():
        return None
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def check_install_scripts(
    package_dir: Path,
    source_dir: Path,
    findings: list[Finding],
) -> list[Finding]:
    """Check matched package.json for newly introduced or modified install scripts."""
    pkg_json_path = package_dir / "package.json"
    src_json_path = source_dir / "package.json"

    pkg_data = _load_json(pkg_json_path)
    src_data = _load_json(src_json_path)

    for finding in findings:
        if finding.file != "package.json":
            continue

        if pkg_data is None or src_data is None:
            continue

        pkg_scripts = pkg_data.get("scripts")
        if not isinstance(pkg_scripts, dict):
            pkg_scripts = {}

        src_scripts = src_data.get("scripts")
        if not isinstance(src_scripts, dict):
            src_scripts = {}

        suspicious = []
        for script_name in sorted(INSTALL_SCRIPTS):
            if script_name in pkg_scripts:
                pkg_cmd = str(pkg_scripts[script_name])
                if script_name not in src_scripts:
                    suspicious.append(f'"{script_name}": "{pkg_cmd}"')
                elif str(src_scripts[script_name]) != pkg_cmd:
                    suspicious.append(f'"{script_name}": "{pkg_cmd}"')

        if suspicious:
            finding.status = Status.SUSPICIOUS
            finding.reason = "install-script"
            finding.snippet = ", ".join(suspicious)
        else:
            finding.status = Status.EXPECTED
            finding.reason = "matched"

    return findings


def check_unknown_files(
    package_dir: Path,
    source_dir: Path,
    findings: list[Finding],
) -> list[Finding]:
    """Enrich unknown-file findings with file content snippets."""
    for finding in findings:
        if finding.reason != "unknown-file":
            continue

        finding.status = Status.SUSPICIOUS
        file_path = package_dir / finding.file

        if file_path.is_file():
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                finding.snippet = content[:200]
            except Exception:
                finding.snippet = None
        else:
            finding.snippet = None

    return findings


def check_obfuscation(
    package_dir: Path,
    source_dir: Path,
    findings: list[Finding],
) -> list[Finding]:
    """Check package files for obfuscated code patterns."""
    for finding in findings:
        if finding.status != Status.EXPECTED:
            continue

        if Path(finding.file).suffix.lower() not in JS_EXTENSIONS:
            continue

        file_path = package_dir / finding.file
        if not file_path.is_file():
            continue

        try:
            with file_path.open("r", encoding="utf-8", errors="replace") as f:
                for line_idx, line in enumerate(f, start=1):
                    # Check huge line heuristic
                    clean_line = line.rstrip("\r\n")
                    if len(clean_line) > HUGE_LINE_THRESHOLD:
                        finding.status = Status.SUSPICIOUS
                        finding.reason = "obfuscation"
                        finding.line = line_idx
                        finding.snippet = clean_line.strip()[:200]
                        break

                    # Check hexadecimal escape heuristic (>= 3 matches)
                    hex_count = len(HEX_ESCAPE_PATTERN.findall(line))
                    if hex_count >= 3:
                        finding.status = Status.SUSPICIOUS
                        finding.reason = "obfuscation"
                        finding.line = line_idx
                        finding.snippet = line.strip()[:200]
                        break

                    # Check eval heuristic
                    if EVAL_PATTERN.search(line):
                        finding.status = Status.SUSPICIOUS
                        finding.reason = "obfuscation"
                        finding.line = line_idx
                        finding.snippet = line.strip()[:200]
                        break
        except Exception:
            continue

    return findings


def apply_rules(
    package_dir: Path,
    source_dir: Path,
    findings: list[Finding],
) -> list[Finding]:
    """Apply detection rules to enrich findings."""
    findings = check_install_scripts(package_dir, source_dir, findings)
    findings = check_unknown_files(package_dir, source_dir, findings)
    findings = check_obfuscation(package_dir, source_dir, findings)
    return findings
