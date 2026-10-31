"""Command-line interface for pkgcheck."""

from pkgcheck import __version__


def main() -> int:
    """Entry point for the pkgcheck CLI."""
    print(f"pkgcheck v{__version__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())