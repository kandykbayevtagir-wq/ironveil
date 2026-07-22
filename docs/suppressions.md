# Suppressions

Suppressions are explicit, reviewable exceptions. Every suppression requires a reason and may
have an expiry. Expired entries produce warnings rather than silently remaining effective.

## Inline suppression

Place the directive near the intentional value using the comment syntax of the file:

```text
# ironveil: allow IV-SEC-001 reason="synthetic fixture" expires="2027-01-01"
```

The rule ID must match the finding. A directive without `reason` is invalid as a suppression.
Use ISO `YYYY-MM-DD` for expiry. Inline directives are appropriate for a stable, local construct
whose context should be obvious during review.

## Configuration allowlist

Use `.ironveil.toml` for a controlled path pattern:

```toml
[[allowlist]]
rule = "IV-SEC-001"
path = "tests/fixtures/**"
reason = "Purpose-built synthetic AWS detector fixtures"
expires = "2027-01-01"
```

`rule = "*"` is supported but rarely appropriate. Path globs are root-relative. Prefer one rule
and the narrowest path possible. Multiple precise entries are easier to audit than a broad test
tree exclusion.

## Review requirements

Before approving a suppression, verify:

1. The value cannot authenticate and was not copied from a real credential.
2. The finding is expected in this exact context.
3. Fixing or restructuring the content is not safer.
4. The rule and path scope are minimal.
5. The reason explains evidence, not convenience.
6. The expiry matches a real review date when the condition is temporary.

`ironveil doctor` reports active, expired, and non-expiring configuration-allowlist entries.
Inline directives are evaluated during scans and shown in reports rather than counted by doctor.
HTML reports show suppression state without exposing matched values. Non-expiring entries are
allowed but should remain conspicuous in review.

Suppressions differ from baselines: a suppression asserts that a specific context is allowed;
a baseline records acknowledged unresolved findings. Neither is a substitute for rotating a
credential or fixing a vulnerable configuration.
