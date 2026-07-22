# SARIF

IronVeil emits SARIF 2.1.0 for GitHub Code Scanning and other compatible consumers:

```console
ironveil scan . --format sarif --output ironveil.sarif
```

Each result includes the stable IronVeil rule ID, a physical file location, masked message text,
severity mapping, and a deterministic partial fingerprint. The tool driver contains rule name,
description, remediation, references, category, original IronVeil severity, and confidence.

## Severity mapping

SARIF has fewer portable levels than IronVeil:

| IronVeil | SARIF level |
| --- | --- |
| `critical`, `high` | `error` |
| `medium` | `warning` |
| `low`, `info` | `note` |

The original value remains in rule or result properties so downstream tooling can distinguish
critical from high. Policy is evaluated by IronVeil before serialization; SARIF level does not
change the process exit code.

## GitHub Code Scanning

The bundled action uploads SARIF when the caller grants:

```yaml
permissions:
  contents: read
  security-events: write
```

For a manual workflow:

```yaml
- name: Generate SARIF
  run: ironveil scan . --format sarif --output ironveil.sarif --no-fail
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81 # v4.37.3
  with:
    sarif_file: ironveil.sarif
    category: ironveil
```

Pin the upload action to a reviewed full commit SHA in production. The `--no-fail` example lets
the upload step run; enforce policy in a separate IronVeil step or use the bundled action, which
generates reports before returning the original scan status.

Do not place complete evidence in SARIF properties, fixes, code flows, or snippets. Code Scanning
retains and displays uploaded content according to repository settings.
