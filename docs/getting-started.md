# Getting started

## Requirements

IronVeil supports Python 3.11, 3.12, and 3.13. Git is optional for a working-tree scan and
required for staged, diff, commit, history, tracked-only, and hook workflows.

Install in an isolated environment:

```console
pipx install ironveil
```

Before the first PyPI release, install a reviewed source checkout:

```console
python -m pip install .
```

Confirm the environment:

```console
ironveil --version
ironveil doctor
```

`doctor` reports the Python version, Git availability and repository state, configuration
validity, report write access, dependency-network availability, and suppression counts. A
failed online check does not enable networking for later scans.

## First scan

From a repository root:

```console
ironveil .
```

This is shorthand for `ironveil scan .`. With no configuration IronVeil:

- respects `.gitignore`;
- does not follow symlinks outside the root;
- skips binary and oversized content according to safe defaults;
- performs no network request;
- shows masked evidence and a deterministic summary;
- exits `1` only when a finding crosses the default policy threshold.

Generate a portable report without changing the policy result:

```console
ironveil scan . --format html --output ironveil-report.html
```

Use `--no-fail` only when report generation must continue despite findings. Execution and
configuration errors still need attention.

## Read a finding

A finding includes a stable rule ID, severity, confidence, file and line, a masked description,
and remediation. Severity describes likely impact. Confidence describes detector certainty.
Policy evaluates both independently; a critical low-confidence finding can be excluded by a
medium confidence minimum, while a high-confidence medium finding can remain visible without
failing a `high` threshold.

For a suspected credential:

1. Do not paste it into an issue or chat.
2. Revoke or rotate it with the provider.
3. Find where it was used and review access logs.
4. Remove it from the current tree.
5. Scan reachable history and coordinate any rewrite.
6. Store the replacement in an approved secret manager.

## Add configuration only when needed

```console
ironveil init
```

This creates `.ironveil.toml` with explicit defaults. Review and commit the file if it defines
team policy. CLI options take precedence over file values. Unknown fields and invalid enum
values are errors rather than silently ignored settings.

Continue with [Configuration](configuration.md), [Git history scanning](git-history.md), or
[GitHub Actions](github-actions.md).
