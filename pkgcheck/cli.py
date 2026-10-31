"""Command-line interface for pkgcheck."""

import argparse
from pathlib import Path
import sys

from pkgcheck import __version__
from pkgcheck.compare import list_package_files, list_source_files, match_files
from pkgcheck.explain import explain_findings
from pkgcheck.report import exit_code_for_findings, render_findings
from pkgcheck.rules import apply_rules


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for pkgcheck CLI."""
    parser = argparse.ArgumentParser(
        prog="pkgcheck",
        description="Compare an npm package with its source repository to detect suspicious discrepancies.",
    )
    parser.add_argument(
        "-p",
        "--package",
        type=Path,
        help="Path to the unpacked npm package directory",
    )
    parser.add_argument(
        "-s",
        "--source",
        type=Path,
        help="Path to the source repository directory",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as a JSON array instead of a table",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Generate AI-powered security explanations for suspicious findings using local Gemma",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"pkgcheck v{__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the pkgcheck CLI."""
    if argv is None:
        if any("pytest" in arg for arg in sys.argv):
            argv = []
        else:
            argv = sys.argv[1:]

    parser = build_parser()

    # If no arguments provided, display help and exit cleanly
    if not argv:
        parser.print_help()
        return 0

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    # Validate that both package and source arguments are provided
    if not args.package or not args.source:
        print("Error: Both --package and --source are required.", file=sys.stderr)
        return 2

    # Validate package directory
    if not args.package.exists():
        print(f"Error: Package path does not exist: {args.package}", file=sys.stderr)
        return 2
    if not args.package.is_dir():
        print(f"Error: Package path is not a directory: {args.package}", file=sys.stderr)
        return 2

    # Validate source directory
    if not args.source.exists():
        print(f"Error: Source path does not exist: {args.source}", file=sys.stderr)
        return 2
    if not args.source.is_dir():
        print(f"Error: Source path is not a directory: {args.source}", file=sys.stderr)
        return 2

    # 1. Compare: list package and source files, and match them
    pkg_files = list_package_files(args.package)
    src_files = list_source_files(args.source)
    findings = match_files(pkg_files, src_files)

    # 2. Apply rules
    findings = apply_rules(args.package, args.source, findings)

    # 3. Explain findings if requested
    if args.explain:
        findings = explain_findings(findings)

    # 4. Render findings
    format_type = "json" if args.json else "table"
    rendered = render_findings(findings, format=format_type)
    print(rendered)

    # 5. Return exit code based on findings
    return exit_code_for_findings(findings)


if __name__ == "__main__":
    raise SystemExit(main())