# Hacktoberfest Hack Day — Sonipat

## Team

**Team Name:** OpenSourcers

### Team Members

- Animesh Priyanshu
- Rishabh Singh
- N.Abhishek Kumar
- Parv Verma

---

## Problem Statement

### P4 — Does the package match its source?

We are building a tool that compares a published software package with its corresponding source repository/version.

The tool will identify differences between the source and the published package, such as:

- Unexpected files in the published package
- Missing files or artifacts
- Differences in package metadata
- Unexpected installation scripts such as `postinstall`
- Other suspicious release artifacts

The system will provide evidence for detected differences and explain them in a clear, maintainer-friendly way.

---

## Open-Weight Model

**Model:** `[MODEL NAME]`

### Why are we using it?

We will use the open-weight model to analyze the differences detected by our comparison engine and generate a clear explanation for maintainers.

The comparison itself will be based on deterministic evidence from the source repository and published package. The model will be used to interpret that evidence, summarize suspicious differences, and explain why a particular difference may require investigation.

We selected this model because it provides a suitable balance of **reasoning capability, response quality, and practical inference requirements** for our 12-hour implementation.