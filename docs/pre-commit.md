# Pre-commit

IronVeil can scan only staged additions before a commit. This is fast feedback, not a replacement
for a protected CI scan: local hooks can be skipped, and they see only the developer's local Git
state.

## pre-commit framework

Add the released repository hook to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/kandykbayevtagir-wq/ironveil
    rev: v1.0.0
    hooks:
      - id: ironveil
```

Pin an exact release and let your normal dependency update process propose changes. Stage the
files you want to validate, then run:

```console
pre-commit install
pre-commit run ironveil
```

The hook entry invokes `ironveil pre-commit`, asks Git for the staged zero-context diff, and does
not rely on filenames passed by pre-commit. Restage a corrected file before retrying.

## Managed Git hook

For repositories that do not use the framework:

```console
ironveil install-hook
```

IronVeil writes a small marked hook only when no conflicting hook exists. If a non-IronVeil hook
already exists, installation stops with guidance. To make replacement explicit while preserving
the old file:

```console
ironveil install-hook --backup-existing
```

This creates `pre-commit.ironveil-backup` and refuses to overwrite an existing backup. Review and
merge hook logic manually when the repository already has important checks; chaining separate
hook managers is often safer than replacement.

## Policy guidance

Keep the local policy aligned with CI through the committed `.ironveil.toml`. A baseline may be
used, but new staged findings should still fail. Avoid `--no-fail` in the hook because it turns
the check into an informational message that developers can easily miss.

If a synthetic fixture is intentional, add a narrow, reasoned suppression rather than weakening
the rule or excluding the entire test directory. See [Suppressions](suppressions.md).
