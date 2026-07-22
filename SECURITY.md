# Security policy

IronVeil processes untrusted repositories and security findings. Reports about vulnerabilities
in IronVeil itself should be handled privately until a fix and disclosure plan are ready.

## Supported versions

Before the first stable release, only the newest `0.1.x` release receives security fixes. The
`main` branch is development code and is not a supported release. After a new patch is
available, users should upgrade rather than relying on an affected version.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/kandykbayevtagir-wq/ironveil/security/advisories/new).
Include:

- the affected version or commit;
- the operating system and Python version;
- the impact and required attacker capabilities;
- minimal reproduction steps using synthetic, nonfunctional values;
- any suggested mitigation.

Do not open a public issue for path escape, output disclosure, command execution, masking
bypass, unsafe network behavior, or supply-chain compromise. Do not send a real credential,
private repository, complete scan report, or sensitive Git object. A minimal synthetic
repository or redacted patch is preferred.

Maintainers will acknowledge a report as capacity permits, validate the issue, coordinate a
fix, and credit the reporter unless anonymity is requested. No response-time guarantee is
made by this volunteer project. If a report is rejected, the maintainer should explain why.

## Coordinated disclosure

Please allow time for supported releases and advisories to be prepared before public
disclosure. The reporter and maintainer should agree on scope and timing. If active
exploitation is suspected, say so clearly in the private report.

## Security invariants

Changes must preserve these properties:

- Default scans do not use the network.
- Scanned content is data: it is not imported, evaluated, built, or installed.
- Subprocesses use explicit argument lists; repository data is never passed to `shell=True`.
- A symlink or resolved path cannot escape the selected scan root.
- Matched secret values are masked in terminal, JSON, SARIF, HTML, JUnit, logs, and tests.
- HTML output escapes repository-controlled strings and is self-contained.
- Cache and baseline records do not store complete matched secrets.
- Online dependency checks send package coordinates only and require explicit opt-in.

The detailed attacker model and trust boundaries are in [docs/threat-model.md](docs/threat-model.md).

## Release and supply-chain practice

Release tags must match the package version. The release workflow validates tests, lint,
typing, documentation, the wheel, and the source distribution before creating a draft GitHub
release. Release assets include SHA-256 checksums and an SPDX JSON SBOM.

PyPI publication is a separate manual workflow decision and uses an environment named `pypi`
with OpenID Connect Trusted Publishing. The workflow contains no long-lived PyPI token and
will not bypass a missing Trusted Publisher configuration. Maintainers should protect the
environment with reviewers, require protected tags, verify checksums, and sign or attest the
tag and release assets using their established release identity.

GitHub workflows use minimal job permissions. External actions are pinned to full commit SHAs
and tracked by Dependabot. CodeQL, dependency review, IronVeil self-scan, and OpenSSF Scorecard
provide independent signals; none is a substitute for review.
