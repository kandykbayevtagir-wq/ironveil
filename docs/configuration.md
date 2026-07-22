# Configuration

IronVeil works without configuration. At startup it reads `ROOT/.ironveil.toml` when present,
unless `--config PATH` selects another file. Command-line values override TOML values.

Unknown fields, malformed regular expressions, duplicate custom rule IDs, invalid categories,
and out-of-range numbers stop the scan with exit code `2`. This strict behavior prevents a
misspelled security control from appearing active.

The packaged JSON Schema is available at `ironveil/schemas/config.schema.json` for editor and CI
validation. It mirrors the same numeric bounds, field names, enums, and mutually exclusive scan
options enforced by the TOML loader; TOML must first be parsed to a JSON-compatible object.

## Complete example

```toml
[scan]
max_size_mb = 10
workers = 8
respect_gitignore = true
follow_symlinks = false
scan_binary = false
tracked_only = false
all_files = false
use_cache = true
exclude = ["docs/generated/**", "tests/fixtures/large/**"]

[policy]
fail_severity = "high"
minimum_confidence = "medium"
fail_on = ["secret", "dependency", "iac", "scan-error"]
no_fail = false

[history]
enabled = false
max_commits = 500

[dependencies]
online = false
timeout_seconds = 10
retries = 1

[ui]
open_browser = true
host = "127.0.0.1"
port = 8765

[[allowlist]]
rule = "IV-SEC-001"
path = "tests/fixtures/**"
reason = "Purpose-built synthetic detector fixture"
expires = "2027-01-01"

[[rules]]
id = "CUSTOM-001"
name = "Internal API key"
category = "secret"
severity = "high"
confidence = "high"
regex = "internal_[A-Za-z0-9]{32}"
message = "Possible internal API key"
remediation = "Store the value in the company secret manager"
```

## Scan settings

`max_size_mb` is bounded from `0.001` to `1024`; larger files are reported or skipped rather
than read without limit. `workers` accepts `1`–`256`. `follow_symlinks` does not permit an
escape from the root even when enabled. `scan_binary` opts into content that may be noisy;
path metadata rules can still inspect a binary filename without reading its body.

`tracked_only` and `all_files` express opposite discovery intents and should not both be used.
Exclusions use root-relative glob patterns. Keep exclusions narrow and review them like code;
an exclusion has no reason or expiry metadata, so use an allowlist when an auditable finding
exception is more appropriate.

## Policy settings

`fail_severity` and `minimum_confidence` form independent thresholds. `fail_on` limits failure
to selected categories while still allowing reporters to show other findings. `no_fail` is
useful for inventory jobs, but should not be the default on a protected branch.

## History and dependencies

History scanning remains off during ordinary tree scans unless explicitly requested. Its
default bound is 500 commits. Online dependency checks are also off by default. When enabled,
timeouts accept `0.1`–`120` seconds and retries accept `0`–`5`.

## UI settings

The host is intentionally fixed to `127.0.0.1`; any other value is a configuration error. This
prevents a report server from being exposed to the local network by a repository-controlled
configuration file.

See [Suppressions](suppressions.md) and [Writing custom rules](writing-custom-rules.md).
