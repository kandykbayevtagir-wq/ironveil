# Built-in rules

Every finding has a stable ID, category, severity, confidence, description, remediation,
references, and detection type. IDs are compatibility surfaces: an ID is not reused for a new
meaning. Severity describes potential impact; confidence describes detector precision. The
installed reporter is the source of truth for full metadata.

## Secret rules

| ID | Detector |
| --- | --- |
| `IV-SEC-001` | AWS access key ID |
| `IV-SEC-002` | GitHub classic token |
| `IV-SEC-003` | GitHub fine-grained token |
| `IV-SEC-004` | GitLab personal access token |
| `IV-SEC-005` | Google API key |
| `IV-SEC-006` | Google service-account private key |
| `IV-SEC-007` | Azure Storage account key |
| `IV-SEC-008` | OpenAI API key |
| `IV-SEC-009` | Anthropic API key |
| `IV-SEC-010` | Stripe secret key |
| `IV-SEC-011` | Slack token |
| `IV-SEC-012` | Slack incoming webhook |
| `IV-SEC-013` | Discord webhook |
| `IV-SEC-014` | Telegram bot token |
| `IV-SEC-015` | Twilio auth token |
| `IV-SEC-016` | SendGrid API key |
| `IV-SEC-017` | Firebase credential |
| `IV-SEC-018` | JSON Web Token |
| `IV-SEC-019` | Bearer token |
| `IV-SEC-020` | Database URL with credentials |
| `IV-SEC-021` | RSA private key |
| `IV-SEC-022` | OpenSSH private key |
| `IV-SEC-023` | EC private key |
| `IV-SEC-024` | PGP private key |
| `IV-SEC-025` | Password assignment |
| `IV-SEC-026` | API token assignment |
| `IV-SEC-027` | High-entropy credential candidate |

Provider-specific patterns run before generic assignment and entropy checks to avoid duplicate
findings. Explicit placeholders such as `your-token-here`, `dummy`, `redacted`, and purpose-built
synthetic fixture markers are filtered narrowly. Entropy detection requires a secret-like variable
context, sufficient character variety, and a threshold adjusted for documentation and lockfiles.
This lowers noise but means entropy alone will not detect every unknown token.

## File and repository rules

| ID | Detector |
| --- | --- |
| `IV-FILE-001` | Environment file |
| `IV-FILE-002` | Credential document |
| `IV-FILE-003` | SSH private-key file |
| `IV-FILE-004` | Private-key or certificate container |
| `IV-FILE-005` | Keystore file |
| `IV-FILE-006` | Database dump |
| `IV-FILE-007` | Backup archive |
| `IV-FILE-008` | Debug log |
| `IV-FILE-009` | Local configuration file |
| `IV-FILE-010` | Oversized repository file |
| `IV-FILE-011` | Generated or dependency directory |

Path rules can report a risky filename without opening the content. Generated directories that
are correctly ignored remain quiet in a default scan and become visible with `--all-files`.
Filename detection is a review signal: a `.pem` file may contain a public certificate, which is
why relevant rules can have medium confidence.

## Dependency rules

| ID | Detector |
| --- | --- |
| `IV-DEP-001` | Unpinned dependency |
| `IV-DEP-002` | Wildcard or floating dependency |
| `IV-DEP-003` | Git dependency |
| `IV-DEP-004` | Insecure dependency source |
| `IV-DEP-005` | Suspicious package name |
| `IV-DEP-006` | Install lifecycle script |
| `IV-DEP-007` | Missing lockfile integrity |
| `IV-DEP-008` | Local or editable dependency |
| `IV-DEP-100` | Known vulnerable dependency reported by explicit OSV lookup |

Rules `001`–`008` are offline hygiene checks. `IV-DEP-100` exists only when `--online` returns an
advisory for an extracted exact coordinate; it is not evidence that other packages are safe.

## Dockerfile rules

| ID | Detector |
| --- | --- |
| `IV-DOCKER-001` | Explicit root user |
| `IV-DOCKER-002` | No `USER` instruction |
| `IV-DOCKER-003` | Floating base-image tag |
| `IV-DOCKER-004` | Remote script piped to a shell |
| `IV-DOCKER-005` | World-writable permissions |
| `IV-DOCKER-006` | Sensitive file copied into image |
| `IV-DOCKER-007` | `ADD` used for a local source |
| `IV-DOCKER-008` | No `HEALTHCHECK` instruction |
| `IV-DOCKER-009` | Package-manager cache retained |

Missing `USER` and `HEALTHCHECK` are structural checks over the final document. Multistage intent
and platform-supplied health checks still require human interpretation.

## GitHub Actions rules

| ID | Detector |
| --- | --- |
| `IV-GHA-001` | Repository permissions set to `write-all` |
| `IV-GHA-002` | Unsafe `pull_request_target` checkout |
| `IV-GHA-003` | Secrets combined with untrusted pull-request data |
| `IV-GHA-004` | Third-party action not pinned to a full commit |
| `IV-GHA-005` | Shell interpolation of untrusted event data |
| `IV-GHA-006` | Checkout persists the GitHub token |
| `IV-GHA-007` | Broad write permission |

Repository-owned local actions and selected GitHub-owned actions are interpreted with context;
pinning and permission findings remain review signals rather than a complete workflow taint
analysis.

## Terraform rules

| ID | Detector |
| --- | --- |
| `IV-TF-001` | Public CIDR exposes a sensitive port |
| `IV-TF-002` | Public storage configuration |
| `IV-TF-003` | Encryption explicitly disabled |
| `IV-TF-004` | Hardcoded provider credential |
| `IV-TF-005` | Overly permissive IAM policy |
| `IV-TF-006` | Security group open to all traffic |

## Kubernetes rules

| ID | Detector |
| --- | --- |
| `IV-K8S-001` | Privileged container |
| `IV-K8S-002` | Host network namespace |
| `IV-K8S-003` | Host process namespace |
| `IV-K8S-004` | `hostPath` volume |
| `IV-K8S-005` | Container permitted to run as root |
| `IV-K8S-006` | Privilege escalation allowed |
| `IV-K8S-007` | Container resource limits missing |
| `IV-K8S-008` | Floating container image |
| `IV-K8S-009` | Unsafe Linux capability |

Infrastructure checks use lightweight, explainable parsing rather than a full Docker, YAML, or
HCL evaluator. They do not resolve templates, variables, modules, admission policy, or runtime
defaults. Use native validators and policy engines for authoritative deployment decisions.

## Rule changes and exceptions

New built-in rules receive new IDs. Detector precision fixes keep the ID when the underlying risk
meaning is unchanged and include regression tests. Use [suppressions](suppressions.md) for a narrow
intentional context and [baselines](baseline.md) for acknowledged unresolved findings. Neither
changes the rule metadata or makes a credential safe.
