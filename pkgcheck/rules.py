"""Detection rules for pkgcheck."""

import json
from pathlib import Path

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


def apply_rules(
    package_dir: Path,
    source_dir: Path,
    findings: list[Finding],
) -> list[Finding]:
    """Apply detection rules to enrich findings."""
    return check_install_scripts(package_dir, source_dir, findings)
