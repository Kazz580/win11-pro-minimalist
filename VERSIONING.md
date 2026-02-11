# Versioning Policy

This repo uses **Semantic Versioning**: `MAJOR.MINOR.PATCH`

## When to bump versions

### MAJOR (X.0.0)
Bump MAJOR when you make a breaking change, such as:
- removing a component previously guaranteed to remain (e.g., Microsoft Store / Windows Update)
- changing defaults in a way that materially changes outcomes
- renaming/relocating primary script entrypoint in a way that breaks automation

### MINOR (0.Y.0)
Bump MINOR when you add functionality in a backward-compatible way:
- new debloat targets (additional Appx removals)
- new policies/toggles
- new logging/auditing features

### PATCH (0.0.Z)
Bump PATCH for backward-compatible fixes:
- bug fixes (typos, quoting, idempotency fixes)
- better detection logic
- safer guardrails (error handling improvements)

## Changelog discipline
- Every release must update `CHANGELOG.md`
- Prefer grouping items by **Added / Changed / Fixed / Removed / Security**
- Optionally tag releases: `v1.4.0`, etc.
