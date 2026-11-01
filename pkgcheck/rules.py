"""Detection rules for pkgcheck."""

import json
from pathlib import Path
import re

from pkgcheck.constants import (
    INSTALL_SCRIPTS,
    JS_EXTENSIONS,
    HUGE_LINE_THRESHOLD,
    HEX_ESCAPE_PATTERN,
    EVAL_PATTERN,
    BUILD_DIRS,
    BUILD_EXTENSIONS,
    SOURCE_EXTENSIONS,
)
from pkgcheck.models import Finding, Status
from pkgcheck.severity import apply_severity_to_findings


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


def _is_build_artifact(rel_path: str) -> bool:
    """Check if a relative path matches build output directory or artifact suffix."""
    p = Path(rel_path)
    if any(part in BUILD_DIRS for part in p.parts[:-1]):
        return True
    if any(rel_path.endswith(ext) for ext in BUILD_EXTENSIONS):
        return True
    return False


def _has_matching_source(rel_path: str, source_dir: Path) -> bool:
    """Determine whether a build artifact corresponds to an actual source file."""
    p = Path(rel_path)
    parts = list(p.parts)
    if parts and parts[0] in BUILD_DIRS:
        parts = parts[1:]
    if not parts:
        return False

    filename = parts[-1]
    parent_path = Path(*parts[:-1]) if len(parts) > 1 else Path()

    # Normalize build suffixes to determine the base stem
    base_name = filename
    for suffix in (
        ".min.js.map",
        ".min.css.map",
        ".js.map",
        ".css.map",
        ".map",
        ".min.js",
        ".min.css",
        ".d.ts",
    ):
        if filename.endswith(suffix):
            base_name = filename[: -len(suffix)]
            break
    else:
        base_name = Path(filename).stem

    # Candidate extensions to check in source
    candidate_exts = sorted(SOURCE_EXTENSIONS)
    if filename.endswith(".min.css") or filename.endswith(".css"):
        candidate_exts.append(".css")

    # Check candidates under src/ and root of source_dir
    for ext in candidate_exts:
        candidate_name = f"{base_name}{ext}"
        if (source_dir / "src" / parent_path / candidate_name).is_file():
            return True
        if (source_dir / parent_path / candidate_name).is_file():
            return True

    # Also check exact filename under src/ and root
    if (source_dir / "src" / parent_path / filename).is_file():
        return True
    if (source_dir / parent_path / filename).is_file():
        return True

    return False


def _has_dangerous_obfuscation(file_path: Path) -> bool:
    """Check if file contains eval() or >= 3 hex escapes on any line."""
    if not file_path.is_file():
        return False
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if EVAL_PATTERN.search(line):
                    return True
                if len(HEX_ESCAPE_PATTERN.findall(line)) >= 3:
                    return True
    except Exception:
        return False
    return False


def check_build_output(
    package_dir: Path,
    source_dir: Path,
    findings: list[Finding],
) -> list[Finding]:
    """Reclassify legitimate build artifacts that match source and are not obfuscated."""
    for finding in findings:
        if finding.reason not in {"unknown-file", "obfuscation"}:
            continue

        if not _is_build_artifact(finding.file):
            continue

        if not _has_matching_source(finding.file, source_dir):
            continue

        file_path = package_dir / finding.file
        if _has_dangerous_obfuscation(file_path):
            continue

        finding.status = Status.EXPECTED
        finding.reason = "build-output"
        finding.snippet = None
        finding.line = None

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
    findings = check_build_output(package_dir, source_dir, findings)

    # Apply severity assessment
    from pkgcheck.severity import apply_severity_to_findings
    findings = apply_severity_to_findings(findings, package_dir, source_dir)

    return findings