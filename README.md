<p align="center">
  <img src="https://raw.githubusercontent.com/kandykbayevtagir-wq/ironveil/main/assets/logo.svg" width="116" height="116" alt="IronVeil shield logo">
</p>

# IronVeil

Repository security before secrets become incidents.

IronVeil is a local-first Python scanner for secrets, sensitive files, Git history,
dependency hygiene, and common repository misconfigurations. It produces stable findings
for people, CI systems, and GitHub Code Scanning without sending source code to a service.

> IronVeil is preparing its first `0.1.0` preview. Until a package is published, install
> from a checked-out release or commit rather than assuming the PyPI name is available.

![Synthetic IronVeil terminal report](https://raw.githubusercontent.com/kandykbayevtagir-wq/ironveil/main/assets/terminal-demo.svg)

## Why this project exists

Credentials often reach a repository through an ordinary edit, a staged change, or an old
commit. Related risks—tracked key files, unpinned dependencies, and unsafe infrastructure
defaults—are spread across several tools. IronVeil provides one predictable local command
for a useful first pass, with masked output and explicit policy controls.

The scanner is designed to be understandable. Every finding has a stable rule ID, severity,
confidence, remediation, and fingerprint. Baselines and suppressions require visible intent;
they do not silently erase a result.

## What it checks

- Common service credentials, private-key material, credential-bearing URLs, generic token
  assignments, and high-entropy candidates with contextual filtering.
- Sensitive filenames, oversized files, and generated or vendor directories that should
  normally be ignored.
- The current tree, staged additions, commit additions, ranges, and bounded Git history.
- Python and JavaScript dependency files for risky sources and version hygiene; known
  vulnerability queries are available only with the explicit `--online` option.
- Explainable checks for Dockerfiles, GitHub Actions, Terraform, and Kubernetes manifests.
- Declarative custom regex rules from `.ironveil.toml`; configuration never imports arbitrary
  Python plugins.

## Quick start

```console
pipx install ironveil
ironveil .
```

From a source checkout before the first PyPI release:

```console
python -m pip install .
ironveil scan .
```

No configuration or account is required. The default scan respects `.gitignore`, does not
follow symlinks outside the scan root, limits file reads, and performs no network request.

## Installation

IronVeil supports Python 3.11, 3.12, and 3.13.

```console
pipx install ironveil
pip install ironveil
uvx ironveil scan .
```

Use a virtual environment with `pip` when you do not want a user-level CLI. Pin a release or
commit for CI; do not install an unreviewed moving branch.

## CLI examples

```console
ironveil .                         # equivalent to: ironveil scan .
ironveil scan . --format json --output ironveil-report.json
ironveil staged
ironveil diff origin/main...HEAD
ironveil commit 4f8c2ab
ironveil history . --max-commits 250 --branch main
ironveil dependencies .
ironveil dependencies . --online  # sends package coordinates, not source, to OSV
ironveil doctor
ironveil --help
```

Policy can be set per run:

```console
ironveil scan . \
  --fail-severity high \
  --minimum-confidence medium \
  --fail-on secret,dependency,iac
```

## GitHub Action

After the `v1` action is published, a caller can use:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
      fetch-depth: 0
  - uses: kandykbayevtagir-wq/ironveil@v1
    with:
      path: .
      fail-severity: high
```

The action creates masked SARIF and a portable HTML report, uploads the HTML as an artifact,
attempts a Code Scanning upload, and writes aggregate counts and top rule IDs to the Job
Summary. It omits finding messages and matched values from that summary. Callers that do not
want a SARIF upload can set `upload-sarif: false` and omit `security-events: write`.

See [GitHub Actions](https://github.com/kandykbayevtagir-wq/ironveil/blob/main/docs/github-actions.md)
for reusable workflow and fork behavior.

## Local UI

```console
ironveil ui .
ironveil ui . --no-open --port 8765
ironveil ui . --diff origin/main...HEAD
```

The UI is a static HTML report served only on `127.0.0.1`. It has no CDN or telemetry and does
not transmit repository contents. Treat any report as sensitive metadata even though matched
values are masked.

## Git history

```console
ironveil history . --max-commits 500
ironveil history . --since 2026-01-01 --until 2026-06-30
ironveil history . --all-branches
```

History scans inspect added lines in selected commits and intentionally require bounds. A
finding in history is evidence that a credential may have escaped: deleting it from the
current file does not delete it from Git history. Revoke or rotate the credential first, then
follow an approved history-rewrite process if needed.

## Baseline

```console
ironveil baseline create .
ironveil baseline verify .
ironveil baseline update .
```

`.ironveil-baseline.json` stores stable fingerprints, not matched secret values. With a
baseline, policy evaluation distinguishes existing findings from new ones. Review baseline
changes as security-relevant code changes; a baseline is risk acceptance, not remediation.

## Configuration

`ironveil init` writes an explicit `.ironveil.toml`, but configuration is optional. CLI flags
override file settings.

```toml
[scan]
max_size_mb = 10
workers = 8
respect_gitignore = true
follow_symlinks = false
scan_binary = false
exclude = ["docs/generated/**"]

[policy]
fail_severity = "high"
minimum_confidence = "medium"
fail_on = ["secret", "dependency", "iac", "scan-error"]

[dependencies]
online = false
timeout_seconds = 10
retries = 1
```

See [Configuration](https://github.com/kandykbayevtagir-wq/ironveil/blob/main/docs/configuration.md)
for allowlists, validation rules, and declarative custom rules.

## Output formats

```console
ironveil scan . --format text
ironveil scan . --format json --output ironveil-report.json
ironveil scan . --format sarif --output ironveil.sarif
ironveil scan . --format html --output ironveil-report.html
ironveil scan . --format junit --output ironveil-junit.xml
```

JSON is intended for automation, SARIF 2.1.0 for code-scanning systems, HTML for a portable
local review, and JUnit for CI systems that ingest test results. Output ordering and
fingerprints are deterministic for the same inputs and configuration.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed and policy passed. |
| `1` | New findings violated the selected policy. |
| `2` | Configuration or execution failed. |
| `3` | The scan completed only partially, so the result may be incomplete. |

Use `--no-fail` to generate a report without failing on findings. It does not convert
configuration errors or materially incomplete scans into a trustworthy pass.

## Security model

IronVeil treats the scanned repository as hostile data. It does not import repository Python,
execute manifests, install repository dependencies, or invoke a shell with file content. Git
is invoked with argument lists after ref validation. File discovery confines resolved paths to
the selected root. Reports mask evidence and HTML escapes untrusted text.

Network access is off by default. `dependencies --online` sends only dependency ecosystem,
name, and version coordinates to the OSV batch API, subject to a timeout and bounded retries.
See the [threat model](https://github.com/kandykbayevtagir-wq/ironveil/blob/main/docs/threat-model.md)
and [security policy](https://github.com/kandykbayevtagir-wq/ironveil/blob/main/SECURITY.md).

## Limitations

IronVeil is an early preview and a defense-in-depth check, not proof that a repository is safe.

- Pattern and lightweight structural rules cannot replace review, full language-aware SAST,
  container scanning, cloud posture management, or a managed secret-scanning program.
- Entropy is heuristic. Encoded data can look secret, and low-entropy credentials can evade it.
- Lightweight Dockerfile, workflow, Terraform, and Kubernetes checks do not fully interpret
  each language or evaluate runtime context.
- Offline dependency checks assess file hygiene, not the complete resolved graph. OSV coverage
  depends on available package coordinates and upstream advisory data.
- Git results are limited to reachable commits and the range or bounds selected by the user.
- Masking reduces exposure but report paths, rule IDs, and locations can still be sensitive.

Report false negatives privately when disclosure could create risk. False positives are
welcome as sanitized public bug reports.

## Contributing

Read [CONTRIBUTING.md](https://github.com/kandykbayevtagir-wq/ironveil/blob/main/CONTRIBUTING.md)
before opening a change. New detector fixtures must be synthetic, clearly labelled, and incapable
of authenticating to any service. Security issues belong in
[private vulnerability reporting](https://github.com/kandykbayevtagir-wq/ironveil/blob/main/SECURITY.md),
not a public issue.

## License

Licensed under the
[Apache License 2.0](https://github.com/kandykbayevtagir-wq/ironveil/blob/main/LICENSE).
