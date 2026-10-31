"""Compare package files with source files."""

from pathlib import Path
from pkgcheck.models import Finding, Status


def list_package_files(package_dir: Path) -> list[str]:
    """Return sorted relative paths of all files in package directory."""
    files = []
    for path in package_dir.rglob("*"):
        if path.is_file():
            rel = path.relative_to(package_dir)
            files.append(rel.as_posix())
    return sorted(files)


def list_source_files(source_dir: Path) -> list[str]:
    """Return sorted relative paths of all files in source directory.

    Only skips files where '.git' is one of the path parts.
    Keeps .github/, .gitignore, and other dot-files.
    """
    files = []
    for path in source_dir.rglob("*"):
        if path.is_file():
            rel = path.relative_to(source_dir)
            # Skip only if .git is a path component
            if ".git" not in rel.parts:
                files.append(rel.as_posix())
    return sorted(files)


def match_files(pkg_files: list[str], src_files: list[str]) -> list[Finding]:
    """Match package files to source files and return Findings."""
    pkg_set = set(pkg_files)
    src_set = set(src_files)
    findings = []

    # All unique files sorted to ensure deterministic output
    all_files = sorted(pkg_set | src_set)

    for f in all_files:
        in_pkg = f in pkg_set
        in_src = f in src_set

        if in_pkg and not in_src:
            findings.append(Finding(
                file=f,
                status=Status.SUSPICIOUS,
                reason="unknown-file"
            ))
        elif in_pkg and in_src:
            findings.append(Finding(
                file=f,
                status=Status.EXPECTED,
                reason="matched"
            ))
        elif not in_pkg and in_src:
            findings.append(Finding(
                file=f,
                status=Status.EXPECTED,
                reason="missing-in-package"
            ))

    return findings