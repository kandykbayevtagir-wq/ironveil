# Threat model

## Scope and assets

IronVeil protects against accidental repository exposure and unsafe configuration while trying
not to create a new exposure channel. Assets include credentials in the current tree or Git
history, proprietary source, filesystem data outside the selected root, report confidentiality,
policy integrity, and the developer or CI environment running the scan.

The primary adversarial input is the repository: filenames, symlinks, encodings, text, manifests,
Git refs and objects, configuration, suppression directives, and report strings may all be
crafted. A malicious contributor may control a pull-request checkout but not the trusted workflow
definition or protected baseline. A compromised dependency or action is a separate supply-chain
adversary.

## Trust boundaries

1. **Filesystem boundary:** discovery may read only bounded files whose resolved location remains
   under the selected root.
2. **Git boundary:** Git is a trusted installed executable; refs and repository objects are
   untrusted data passed through validated argument lists.
3. **Configuration boundary:** `.ironveil.toml` is untrusted declarative data. It cannot load
   Python code or select a UI listener beyond localhost.
4. **Reporter boundary:** reporters receive masked finding evidence and must escape output for the
   destination format.
5. **Network boundary:** closed by default. Explicit OSV mode sends package coordinates only.
6. **CI boundary:** the workflow and pinned actions are trusted; the scanned pull-request checkout
   is not. Token permissions must reflect that distinction.

## Threats and controls

| Threat | Primary controls | Residual risk |
| --- | --- | --- |
| Symlink or traversal reads outside root | Resolve and confine paths; do not follow external links | Races on a concurrently modified tree require environmental isolation |
| Repository code execution | No imports, package installs, build commands, manifest evaluation, or `shell=True` | Git and Python themselves remain trusted dependencies |
| Secret disclosure in output | Mask at detection boundary; omit detailed Job Summary fields; escape reporters | Paths, locations, prefixes, and rule types remain sensitive |
| HTML injection or remote loading | HTML escaping, embedded assets, restrictive CSP, no CDN | Browser defects and locally installed extensions are out of scope |
| Git option or shell injection | Validate refs; subprocess argument arrays; `--no-ext-diff`; option terminator | A compromised Git binary is out of scope |
| Denial of service by large or numerous files | Size limits, bounded reads, worker limits, timeouts, cache | A very large adversarial repository can still consume time and disk |
| Regex denial of service | Reviewed bounded patterns and file-size limits | User-supplied custom regex can be computationally expensive |
| Silent policy weakening | Strict config validation; visible baseline/suppressions; expiry warnings | Authorized contributors can still approve unsafe policy changes |
| Unintended network disclosure | Network off by default; explicit `--online`; coordinate-only payload | Package names can be confidential metadata |
| CI token misuse | Minimal job permissions; no unsafe `pull_request_target`; pinned actions | Platform or pinned-action compromise remains possible |
| Cache leakage or poisoning | External per-user directory, config/rule metadata, masked records | Same-account local processes can access or modify cache files |

## Non-goals

IronVeil does not sandbox arbitrary builds because it never needs to build the target. It does not
guarantee detection of every secret, vulnerability, malware sample, or policy violation. It does
not scan running systems, containers, cloud accounts, memory, unreachable remote Git objects, or
third-party artifact stores.

## Safe deployment

Run on an isolated, patched machine under a least-privileged account. Do not place production
credentials in the environment of a public pull-request job. Protect `.ironveil.toml`, baseline,
workflow, and release changes with review. Restrict artifacts and clear them when no longer
needed. Treat an IronVeil pass as one control in a layered review process.

Security defects in these boundaries should follow the private process in `SECURITY.md`.
