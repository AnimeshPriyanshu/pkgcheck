"""Severity assessment for pkgcheck findings."""

from dataclasses import dataclass
from pathlib import Path
from pkgcheck.models import Finding, Evidence, Severity, Status
from pkgcheck.constants import (
    INSTALL_SCRIPTS,
    BUILD_DIRS,
    BUILD_EXTENSIONS,
    JS_EXTENSIONS,
    HEX_ESCAPE_PATTERN,
    EVAL_PATTERN,
    EXECUTABLE_EXTENSIONS,
)

# Evidence weight constants
WEIGHT_INSTALL_SCRIPT_NEW = 3
WEIGHT_INSTALL_SCRIPT_MODIFIED = 2
WEIGHT_OBFUSCATION_EVAL = 3
WEIGHT_OBFUSCATION_HEX = 2
WEIGHT_OBFUSCATION_LONG_LINE = 1
WEIGHT_UNKNOWN_EXECUTABLE = 2
WEIGHT_UNKNOWN_NON_EXECUTABLE = 1
WEIGHT_CONTENT_DIFF = 0
WEIGHT_BUILD_OUTPUT_VERIFIED = 0  # No positive suspicious weight


# Executable file extensions
EXECUTABLE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".sh", ".py", ".exe", ".bin", ".ps1", ".bat", ".cmd"}


@dataclass
class EvidenceItem:
    """A single piece of evidence contributing to severity."""
    rule: str
    evidence_type: str
    file: str
    description: str
    weight: int


def _collect_evidence_for_finding(
    finding: Finding,
    package_dir: Path,
    source_dir: Path,
) -> list[EvidenceItem]:
    """Collect structured evidence for a finding based on its reason and context."""
    from pkgcheck.constants import (
        INSTALL_SCRIPTS,
        BUILD_DIRS,
        BUILD_EXTENSIONS,
        JS_EXTENSIONS,
        HEX_ESCAPE_PATTERN,
        EVAL_PATTERN,
        EXECUTABLE_EXTENSIONS,
    )
    
    evidence = []
    
    # Get file extension
    ext = Path(finding.file).suffix.lower()
    
    if finding.reason == "install-script":
        evidence.append(EvidenceItem(
            rule="check_install_scripts",
            evidence_type="install-script",
            file=finding.file,
            description=f"New or modified install script detected: {finding.snippet}",
            weight=3,
        ))
    
    elif finding.reason == "obfuscation":
        # Determine which obfuscation pattern triggered
        file_path = package_dir / finding.file
        has_eval = False
        has_hex = False
        has_long_line = False
        
        if file_path.is_file():
            try:
                with file_path.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if EVAL_PATTERN.search(line):
                            has_eval = True
                        if len(HEX_ESCAPE_PATTERN.findall(line)) >= 3:
                            has_hex = True
                        if len(line.rstrip("\r\n")) > 500:
                            has_long_line = True
                        if has_eval and has_hex and has_long_line:
                            break
            except Exception:
                pass
        
        if has_eval:
            evidence.append(EvidenceItem(
                rule="check_obfuscation",
                evidence_type="eval-call",
                file=finding.file,
                description=f"eval() call detected in {finding.file} at line {finding.line}",
                weight=3,
            ))
        if has_hex:
            evidence.append(EvidenceItem(
                rule="check_obfuscation",
                evidence_type="hex-encoding",
                file=finding.file,
                description=f"Hex encoding (\\xNN) detected in {finding.file} at line {finding.line}",
                weight=2,
            ))
        if has_long_line and not has_eval and not has_hex:
            evidence.append(EvidenceItem(
                rule="check_obfuscation",
                evidence_type="long-line",
                file=finding.file,
                description=f"Line exceeding 500 characters in {finding.file} at line {finding.line}",
                weight=1,
            ))
    
    elif finding.reason == "unknown-file":
        ext = Path(finding.file).suffix.lower()
        if ext in {".js", ".mjs", ".cjs", ".ts", ".sh", ".py", ".exe", ".bin", ".ps1", ".bat", ".cmd"}:
            evidence.append(EvidenceItem(
                rule="check_unknown_files",
                evidence_type="unknown-executable",
                file=finding.file,
                description=f"Unknown executable file ({ext}) in package: {finding.file}",
                weight=2,
            ))
        else:
            evidence.append(EvidenceItem(
                rule="check_unknown_files",
                evidence_type="unknown-file",
                file=finding.file,
                description=f"Unknown file ({ext}) in package: {finding.file}",
                weight=1,
            ))
    
    elif finding.reason == "content-diff":
        # Content difference alone gets no positive weight
        # But we can add context evidence with 0 weight
        evidence.append(EvidenceItem(
            rule="compare",
            evidence_type="content-diff",
            file=finding.file,
            description=f"Content differs from source: {finding.snippet}",
            weight=0,
        ))
        
        # Check if snippet contains obfuscation patterns
        if finding.snippet:
            if EVAL_PATTERN.search(finding.snippet):
                evidence.append(EvidenceItem(
                    rule="compare",
                    evidence_type="eval-in-diff",
                    file=finding.file,
                    description="eval() call found in content difference",
                    weight=3,
                ))
            if len(HEX_ESCAPE_PATTERN.findall(finding.snippet)) >= 3:
                evidence.append(EvidenceItem(
                    rule="compare",
                    evidence_type="hex-in-diff",
                    file=finding.file,
                    description="Hex encoding found in content difference",
                    weight=2,
                ))
    
    elif finding.reason == "build-output":
        # Verified build output gets no positive weight
        evidence.append(EvidenceItem(
            rule="check_build_output",
            evidence_type="verified-build-output",
            file=finding.file,
            description=f"Verified build artifact with matching source: {finding.file}",
            weight=0,
        ))
    
    elif finding.reason == "missing-in-package":
        evidence.append(EvidenceItem(
            rule="compare",
            evidence_type="missing-in-package",
            file=finding.file,
            description=f"File present in source but missing from package: {finding.file}",
            weight=0,
        ))
    
    elif finding.reason == "matched":
        evidence.append(EvidenceItem(
            rule="compare",
            evidence_type="identical",
            file=finding.file,
            description=f"File matches source exactly: {finding.file}",
            weight=0,
        ))
    
    return evidence


def calculate_severity(
    finding: Finding,
    package_dir: Path,
    source_dir: Path,
) -> tuple:
    """
    Calculate severity based on structured evidence.
    
    Returns tuple of (Severity, list of EvidenceItem).
    """
    evidence = _collect_evidence_for_finding(finding, package_dir, source_dir)
    
    # Deduplicate evidence by (rule, evidence_type, file) - keep highest weight
    unique_evidence = {}
    for ev in evidence:
        key = (ev.rule, ev.evidence_type, ev.file)
        if key not in unique_evidence or ev.weight > unique_evidence[key].weight:
            unique_evidence[key] = ev
    
    deduped_evidence = list(unique_evidence.values())
    
    # Calculate total weight
    total_weight = sum(ev.weight for ev in deduped_evidence)
    
    # Determine severity
    if total_weight >= 6:
        severity = Severity.CRITICAL
    elif total_weight >= 4:
        severity = Severity.HIGH
    elif total_weight >= 2:
        severity = Severity.MEDIUM
    elif total_weight >= 1:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    
    return severity, deduped_evidence


def apply_severity_to_findings(
    findings: list,
    package_dir: Path,
    source_dir: Path,
) -> list:
    """Apply severity calculation to all findings."""
    from pkgcheck.models import Finding, Evidence, Severity, Status
    for finding in findings:
        severity, evidence = calculate_severity(finding, package_dir, source_dir)
        finding.severity = severity
        finding.evidence = evidence
    return findings


def calculate_severity(
    finding,
    package_dir: Path,
    source_dir: Path,
) -> tuple:
    """
    Calculate severity based on structured evidence.
    
    Returns tuple of (Severity, list of EvidenceItem).
    """
    from pkgcheck.models import Finding, Evidence, Severity, Status
    from pkgcheck.constants import (
        INSTALL_SCRIPTS,
        BUILD_DIRS,
        BUILD_EXTENSIONS,
        JS_EXTENSIONS,
        HEX_ESCAPE_PATTERN,
        EVAL_PATTERN,
        EXECUTABLE_EXTENSIONS,
    )
    from pkgcheck.severity import EvidenceItem
    
    evidence = []
    
    # Get file extension
    ext = Path(finding.file).suffix.lower()
    
    if finding.reason == "install-script":
        evidence.append(EvidenceItem(
            rule="check_install_scripts",
            evidence_type="install-script",
            file=finding.file,
            description=f"New or modified install script detected: {finding.snippet}",
            weight=3,
        ))
    
    elif finding.reason == "obfuscation":
        # Determine which obfuscation pattern triggered
        file_path = package_dir / finding.file
        has_eval = False
        has_hex = False
        has_long_line = False
        
        if file_path.is_file():
            try:
                with file_path.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if EVAL_PATTERN.search(line):
                            has_eval = True
                        if len(HEX_ESCAPE_PATTERN.findall(line)) >= 3:
                            has_hex = True
                        if len(line.rstrip("\r\n")) > 500:
                            has_long_line = True
                        if has_eval and has_hex and has_long_line:
                            break
            except Exception:
                pass
        
        if has_eval:
            evidence.append(EvidenceItem(
                rule="check_obfuscation",
                evidence_type="eval-call",
                file=finding.file,
                description=f"eval() call detected in {finding.file} at line {finding.line}",
                weight=3,
            ))
        if has_hex:
            evidence.append(EvidenceItem(
                rule="check_obfuscation",
                evidence_type="hex-encoding",
                file=finding.file,
                description=f"Hex encoding (\\xNN) detected in {finding.file} at line {finding.line}",
                weight=2,
            ))
        if has_long_line and not has_eval and not has_hex:
            evidence.append(EvidenceItem(
                rule="check_obfuscation",
                evidence_type="long-line",
                file=finding.file,
                description=f"Line exceeding 500 characters in {finding.file} at line {finding.line}",
                weight=1,
            ))
    
    elif finding.reason == "unknown-file":
        ext = Path(finding.file).suffix.lower()
        if ext in {".js", ".mjs", ".cjs", ".ts", ".sh", ".py", ".exe", ".bin", ".ps1", ".bat", ".cmd"}:
            evidence.append(EvidenceItem(
                rule="check_unknown_files",
                evidence_type="unknown-executable",
                file=finding.file,
                description=f"Unknown executable file ({ext}) in package: {finding.file}",
                weight=2,
            ))
        else:
            evidence.append(EvidenceItem(
                rule="check_unknown_files",
                evidence_type="unknown-file",
                file=finding.file,
                description=f"Unknown file ({ext}) in package: {finding.file}",
                weight=1,
            ))
    
    elif finding.reason == "content-diff":
        # Content difference alone gets no positive weight
        # But we can add context evidence with 0 weight
        evidence.append(EvidenceItem(
            rule="compare",
            evidence_type="content-diff",
            file=finding.file,
            description=f"Content differs from source: {finding.snippet}",
            weight=0,
        ))
        
        # Check if snippet contains obfuscation patterns
        if finding.snippet:
            if EVAL_PATTERN.search(finding.snippet):
                evidence.append(EvidenceItem(
                    rule="compare",
                    evidence_type="eval-in-diff",
                    file=finding.file,
                    description="eval() call found in content difference",
                    weight=3,
                ))
            if len(HEX_ESCAPE_PATTERN.findall(finding.snippet)) >= 3:
                evidence.append(EvidenceItem(
                    rule="compare",
                    evidence_type="hex-in-diff",
                    file=finding.file,
                    description="Hex encoding found in content difference",
                    weight=2,
                ))
    
    elif finding.reason == "build-output":
        # Verified build output gets no positive weight
        evidence.append(EvidenceItem(
            rule="check_build_output",
            evidence_type="verified-build-output",
            file=finding.file,
            description=f"Verified build artifact with matching source: {finding.file}",
            weight=0,
        ))
    
    elif finding.reason == "missing-in-package":
        evidence.append(EvidenceItem(
            rule="compare",
            evidence_type="missing-in-package",
            file=finding.file,
            description=f"File present in source but missing from package: {finding.file}",
            weight=0,
        ))
    
    elif finding.reason == "matched":
        evidence.append(EvidenceItem(
            rule="compare",
            evidence_type="identical",
            file=finding.file,
            description=f"File matches source exactly: {finding.file}",
            weight=0,
        ))
    
    # Deduplicate evidence by (rule, evidence_type, file) - keep highest weight
    unique_evidence = {}
    for ev in evidence:
        key = (ev.rule, ev.evidence_type, ev.file)
        if key not in unique_evidence or ev.weight > unique_evidence[key].weight:
            unique_evidence[key] = ev
    
    deduped_evidence = list(unique_evidence.values())
    
    # Calculate total weight
    total_weight = sum(ev.weight for ev in deduped_evidence)
    
    # Determine severity
    if total_weight >= 6:
        severity = Severity.CRITICAL
    elif total_weight >= 4:
        severity = Severity.HIGH
    elif total_weight >= 2:
        severity = Severity.MEDIUM
    elif total_weight >= 1:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    
    return severity, deduped_evidence


def apply_severity_to_findings(
    findings: list,
    package_dir: Path,
    source_dir: Path,
) -> list:
    """Apply severity calculation to all findings."""
    from pkgcheck.models import Finding, Evidence, Severity, Status
    for finding in findings:
        severity, evidence = calculate_severity(finding, package_dir, source_dir)
        finding.severity = severity
        finding.evidence = evidence
    return findings