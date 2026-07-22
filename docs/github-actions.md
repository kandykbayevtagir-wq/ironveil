# GitHub Actions

The IronVeil composite action installs the scanner from the referenced action checkout, scans
the requested path, generates SARIF and HTML, uploads the HTML artifact, optionally uploads
SARIF to Code Scanning, writes a masked Job Summary, and finally enforces IronVeil's exit code.

## Minimal workflow

```yaml
name: Repository security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  ironveil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0
      - uses: kandykbayevtagir-wq/ironveil@v1
        with:
          path: .
          fail-severity: high
          minimum-confidence: medium
```

Use a full release commit SHA in a high-assurance repository and let Dependabot propose updates.
The `v1` example follows the conventional stable-major channel once that channel exists.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Checked-out path to scan. |
| `fail-severity` | `high` | Lowest severity that fails policy. |
| `minimum-confidence` | `medium` | Lowest confidence evaluated by policy. |
| `upload-sarif` | `true` | Attempt Code Scanning upload. |
| `artifact-name` | `ironveil-html-report` | HTML artifact name. |
| `retention-days` | `14` | Artifact retention in days. |

Outputs include `exit-code`, `sarif-path`, `html-path`, and `artifact-url`. Paths refer to the
current runner and are primarily useful to later steps in the same job.

If Code Scanning is unavailable, set `upload-sarif: false` and remove `security-events: write`.
The HTML artifact and policy result remain available. A failed SARIF upload does not turn a
clean scan into a failure, but GitHub records the upload step outcome for investigation.

## Job Summary

The action reads its already-masked SARIF and writes:

- overall exit status;
- total, critical, high, and medium counts;
- up to five most frequent rule IDs;
- the HTML artifact link;
- a local reproduction command.

It deliberately omits messages, evidence, paths, lines, and Git content. This limits accidental
exposure in widely visible workflow summaries. The HTML artifact still contains sensitive
metadata and should have the shortest useful retention.

## Reusable workflow

The repository includes `.github/workflows/reusable-ironveil.yml`. After release, call it with:

```yaml
name: Repository security

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    uses: kandykbayevtagir-wq/ironveil/.github/workflows/reusable-ironveil.yml@v1
    with:
      path: .
      fail-severity: high
      minimum-confidence: medium
```

A called workflow cannot elevate permissions beyond those granted by the caller.

## Pull requests from forks

GitHub limits write tokens for untrusted forks. The scan and HTML artifact can still run, while
the SARIF upload may be unavailable. Do not switch the workflow to `pull_request_target` to get
a write token and then check out untrusted pull-request code; that creates a larger trust
boundary. Run a read-only pull-request scan and upload SARIF on a trusted `push` to the protected
branch instead.

## Self-hosted runners

Current official actions use the Node 24 runtime and require a current Actions runner. Keep the
runner patched, isolate it between repositories, and assume a scanned checkout is hostile. The
scanner does not execute repository content, but any other build step in the job may do so.
Avoid placing long-lived credentials on a runner used for public pull requests.
