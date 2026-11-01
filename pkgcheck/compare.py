"""Compare package files with source files."""

import hashlib
from pathlib import Path
from pkgcheck.models import Finding, Status


def _hash_file(file_path: Path) -> str:
    """Compute SHA-256 hash of a file using chunked reading."""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


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


def match_files(
    pkg_files: list[str],
    src_files: list[str],
    package_dir: Path | None = None,
    source_dir: Path | None = None,
) -> list[Finding]:
    """Match package files to source files and return Findings.

    If package_dir and source_dir are provided, also compare file contents
    via SHA-256 for files present in both directories.
    """
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
            # Compare file contents if directories are provided
            if package_dir is not None and source_dir is not None:
                pkg_path = package_dir / f
                src_path = source_dir / f
                if pkg_path.is_file() and src_path.is_file():
                    pkg_hash = _hash_file(pkg_path)
                    src_hash = _hash_file(src_path)
                    if pkg_hash != src_hash:
                        findings.append(Finding(
                            file=f,
                            status=Status.SUSPICIOUS,
                            reason="content-diff",
                            snippet=f"package: {pkg_hash[:16]}... vs source: {src_hash[:16]}..."
                        ))
                        continue
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