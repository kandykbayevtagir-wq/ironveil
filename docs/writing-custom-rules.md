# Writing custom rules

Version `0.1` supports declarative TOML regex rules. It does not import arbitrary Python plugins
from the scanned repository. This keeps a configuration file from becoming an execution path.

## Define a rule

```toml
[[rules]]
id = "CUSTOM-001"
name = "Internal API key"
description = "An internal API key with the company prefix"
category = "secret"
severity = "high"
confidence = "high"
regex = "internal_[A-Za-z0-9]{32}"
message = "Possible internal API key"
remediation = "Revoke the key and store its replacement in the company secret manager"
```

Required fields are `id`, `name`, `category`, `severity`, `confidence`, `regex`, `message`, and
`remediation`. `description` is optional. IDs must be unique across custom rules. Invalid regular
expressions, enums, or missing values fail configuration with exit code `2`.

## Design guidance

- Use an organization-owned prefix, such as `ACME-SEC-001`; do not use the built-in `IV-` space.
- Match the credential value, not a whole file or multiline block, so evidence can be masked and
  located precisely.
- Add provider or variable-name context when the token shape is generic.
- Bound repetitions and avoid nested ambiguous quantifiers that can cause excessive backtracking.
- Choose severity for impact and confidence for precision; do not inflate either to force policy.
- Give remediation an immediate action, including revocation when the value could authenticate.
- Test realistic positive boundaries and negative examples, placeholders, Unicode, long lines,
  and near misses using values created only for the test.

Custom rules use the same reporting, fingerprint, baseline, suppression, and policy pipeline as
built-in rules. They do not gain network or filesystem access.

## Limitations

Declarative regex rules cannot perform provider validation, cross-file correlation, parsing, or a
custom entropy algorithm. Prefer a small upstream contribution for a broadly useful detector that
needs those capabilities. Python plugin loading may be considered in a future release only with an
explicit trust and packaging model; it is not accepted from `.ironveil.toml`.
