# IronVeil documentation

IronVeil is a local-first scanner for repository secrets, sensitive files, Git changes and
history, dependency hygiene, and common infrastructure misconfigurations. It is intended for
fast developer feedback and predictable CI policy, not as a replacement for language-aware
SAST or a managed security platform.

Start with [Getting started](getting-started.md), then choose the workflow that matches your
use case:

| Goal | Documentation |
| --- | --- |
| Scan a checkout | [CLI reference](cli-reference.md) |
| Review only a change | [Git history scanning](git-history.md) |
| Adopt without failing on old findings | [Baselines](baseline.md) |
| Document an intentional exception | [Suppressions](suppressions.md) |
| Add CI and Code Scanning | [GitHub Actions](github-actions.md) |
| Run before each commit | [Pre-commit](pre-commit.md) |
| Review a portable report | [HTML UI](html-ui.md) |
| Query known dependency vulnerabilities | [Dependency scanning](dependency-scanning.md) |
| Understand trust boundaries | [Threat model](threat-model.md) |

## Operating principles

IronVeil makes no network request during a default scan. It treats repository content as
untrusted data and never imports, evaluates, builds, or installs that content. Matched values
are masked before a finding reaches a reporter. Stable IDs, fingerprints, ordering, schemas,
and exit codes are compatibility surfaces.

The recommended adoption sequence is:

1. Run a text and HTML scan locally.
2. Triage findings and rotate any exposed credential before changing history.
3. Fix findings where practical; baseline only reviewed residual risk.
4. Add a staged pre-commit check.
5. Add the GitHub Action with an explicit policy and protected baseline changes.

## Project status

Version `0.1.0` is a preview. Detectors are deliberately explainable and conservative, but
false positives and false negatives remain possible. Review the [limitations](index.md#project-status)
and report security-sensitive scanner defects through the private process in `SECURITY.md`.
