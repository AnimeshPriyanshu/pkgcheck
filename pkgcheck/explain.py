"""Explain findings using local Gemma model via LM Studio."""

import os
import json
import urllib.request
import urllib.error
from pkgcheck.models import Finding, Status

LM_STUDIO_URL = os.environ.get("LM_STUDIO_URL", "http://127.0.0.1:1234/v1")
MODEL_NAME = os.environ.get("GEMMA_MODEL", "google/gemma-4-e4b")
REQUEST_TIMEOUT = 30  # seconds

FALLBACK_EXPLANATIONS = {
    "install-script": (
        "The package.json contains an install lifecycle script (preinstall, install, or postinstall) "
        "that is not present in the source repository. Attackers often use these scripts to execute "
        "malicious code during package installation."
    ),
    "unknown-file": (
        "A file exists in the published package but not in the source repository. This could indicate "
        "that malicious files were added during the publishing process or that the package was tampered with."
    ),
    "obfuscation": (
        "The file contains obfuscated code patterns such as extremely long lines, hexadecimal escape "
        "sequences, or eval() calls. Obfuscation is commonly used to hide malicious behavior from reviewers."
    ),
    "build-output": (
        "This file appears to be a build artifact (minified JS, TypeScript declarations, source maps) "
        "that has a corresponding source file in the repository. This is expected for compiled packages."
    ),
    "content-diff": (
        "The file exists in both the package and source but their contents differ. This could indicate "
        "unauthorized modifications during the build or publish process."
    ),
    "missing-in-package": (
        "A file exists in the source repository but is missing from the published package. This may be "
        "intentional (e.g., test files, documentation) or could indicate an incomplete publish."
    ),
    "matched": (
        "The file exists in both the package and source repository with identical content. No suspicious "
        "differences detected."
    ),
}


def _build_prompt(finding: Finding) -> str:
    """Build a concise prompt for the Gemma model."""
    status_label = finding.status.value
    snippet = finding.snippet if finding.snippet else "(no snippet available)"

    return (
        "You are a security analyst reviewing an npm package for suspicious differences.\n"
        f"File: {finding.file}\n"
        f"Status: {status_label}\n"
        f"Reason: {finding.reason}\n"
        f"Snippet: {snippet}\n\n"
        "Provide a concise, security-focused explanation (2-3 sentences) of why this finding "
        "is suspicious or expected. Do not include reasoning steps or internal thoughts."
    )


def _call_gemma(prompt: str) -> str:
    """Call LM Studio's OpenAI-compatible chat completions endpoint."""
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "You are a concise security analyst."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 150,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{LM_STUDIO_URL}/chat/completions",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError:
        raise ConnectionError("Cannot connect to LM Studio")
    except TimeoutError:
        raise TimeoutError("Request to LM Studio timed out")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON response from LM Studio")

    # Extract the message content, never expose reasoning_content
    choices = result.get("choices")
    if not choices or not isinstance(choices, list):
        raise ValueError("Invalid response format: missing choices")

    message = choices[0].get("message")
    if not message or not isinstance(message, dict):
        raise ValueError("Invalid response format: missing message")

    content = message.get("content")
    if not content or not isinstance(content, str):
        raise ValueError("Invalid response format: empty or missing content")

    return content.strip()


def _fallback_explanation(finding: Finding) -> str:
    """Return a deterministic fallback explanation based on the finding reason."""
    return FALLBACK_EXPLANATIONS.get(finding.reason, f"Finding: {finding.reason} for file {finding.file}")


def explain_finding(finding: Finding) -> str:
    """
    Explain a finding using the local Gemma model via LM Studio.

    Returns the model's explanation on success, or a deterministic fallback
    explanation if the model is unavailable or returns an invalid response.
    """
    # Only explain SUSPICIOUS findings; EXPECTED findings get no explanation
    if finding.status == Status.EXPECTED:
        return ""

    prompt = _build_prompt(finding)

    try:
        return _call_gemma(prompt)
    except (ConnectionError, TimeoutError, ValueError):
        # Graceful fallback: never crash, always return a useful explanation
        return _fallback_explanation(finding)


def explain_findings(findings: list[Finding]) -> list[Finding]:
    """
    Add explanations to all SUSPICIOUS findings in the list.

    Modifies findings in place and returns the same list for chaining.
    """
    for finding in findings:
        if finding.status == Status.SUSPICIOUS:
            finding.explanation = explain_finding(finding)
        else:
            finding.explanation = ""
    return findings