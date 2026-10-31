#!/usr/bin/env python3
"""Check that PR description has required sections filled out."""

import os
import re
import sys


MODELS_HEADING = "## Models the product uses in this PR"
ASSISTANTS_HEADING = "## AI coding assistant that helped write it"
PLACEHOLDER_PATTERNS = [
    r"\(e\.g\..*?\)",
    r"<!--.*?-->",
]


def parse_pr_body(body: str) -> tuple[str, str]:
    """Parse PR body and return (models, assistants) content.

    Args:
        body: The PR description body text.

    Returns:
        Tuple of (models_text, assistants_text) with whitespace stripped.

    Raises:
        ValueError: If a required section is missing.
    """
    if MODELS_HEADING not in body:
        raise ValueError(f'Missing section: "{MODELS_HEADING}"')
    if ASSISTANTS_HEADING not in body:
        raise ValueError(f'Missing section: "{ASSISTANTS_HEADING}"')

    # Split body into sections by headings (lines starting with ## )
    # Keep the heading with its content
    sections = re.split(r"\n(?=## )", body)

    models = ""
    assistants = ""

    for section in sections:
        section = section.strip()
        if section.startswith(MODELS_HEADING):
            # Remove the heading line and get the content
            content = section[len(MODELS_HEADING):].strip()
            models = content
        elif section.startswith(ASSISTANTS_HEADING):
            content = section[len(ASSISTANTS_HEADING):].strip()
            assistants = content

    return models, assistants


def is_empty_or_placeholder(text: str) -> bool:
    """Check if text is empty or only contains placeholder content."""
    if not text or not text.strip():
        return True
    if text.strip().lower() == "none":
        return False
    stripped = text.strip()
    for pattern in PLACEHOLDER_PATTERNS:
        if re.fullmatch(pattern, stripped, re.DOTALL):
            return True
    return False


def main() -> int:
    pr_body = os.environ.get("PR_BODY", "")
    if not pr_body:
        print("ERROR: PR_BODY environment variable not set", file=sys.stderr)
        return 1

    try:
        models, assistants = parse_pr_body(pr_body)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if is_empty_or_placeholder(models):
        print(
            f'ERROR: Section "{MODELS_HEADING}" is empty or contains only placeholder text',
            file=sys.stderr,
        )
        return 1

    if is_empty_or_placeholder(assistants):
        print(
            f'ERROR: Section "{ASSISTANTS_HEADING}" is empty or contains only placeholder text',
            file=sys.stderr,
        )
        return 1

    print(f"Models: {models}")
    print(f"Assistants: {assistants}")
    return 0


if __name__ == "__main__":
    sys.exit(main())