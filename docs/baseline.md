# Baselines

A baseline records fingerprints of reviewed findings so a team can introduce IronVeil without
pretending existing debt is fixed. It does not store matched values, waive a rule globally, or
change detector behavior.

## Workflow

Create a baseline after triage:

```console
ironveil baseline create .
git add .ironveil-baseline.json
```

Verify that the committed baseline matches a current scan:

```console
ironveil baseline verify .
```

Update only after reviewing additions and removals:

```console
ironveil baseline update .
git diff -- .ironveil-baseline.json
```

The file should be code-reviewed and branch-protected. A large unexplained fingerprint addition
is equivalent to accepting new security debt.

## Fingerprints

Fingerprints are deterministic, one-way identifiers derived from the rule and normalized
finding context. They allow the same logical result to be recognized without persisting a
secret. A detector, normalization, or schema change can intentionally change fingerprints;
such changes require release notes and a reviewed baseline migration.

## Policy behavior

Reports distinguish new, baseline, and suppressed findings. Baseline findings remain visible
because users need an accurate inventory. Policy failure is based on new findings that satisfy
the configured severity, confidence, and category thresholds.

## Safe maintenance

- Fix and remove baseline entries whenever practical.
- Never edit opaque fingerprints merely to make CI green.
- Treat a missing or malformed baseline as a configuration problem, not an empty baseline.
- Run `verify` on protected branches.
- Keep baselines repository-specific; fingerprints are not an organization-wide allowlist.
- Revoke any credential before baselining its finding. A baseline does not reduce exposure.

Use a [suppression](suppressions.md) instead when one well-understood line or path is intentionally
safe and needs a documented reason or expiry.
