# Architecture

IronVeil uses a `src` layout and keeps discovery, detection, policy, and presentation separate.
This makes the trust boundary visible and lets tests exercise each stage without invoking the CLI.

```text
CLI / configuration
        |
        v
discovery or Git source  ->  bounded text / metadata
        |
        v
rule registry            ->  immutable RuleMatch values
        |
        v
scanner                   ->  masked, fingerprinted Finding values
        |
        v
policy                    ->  baseline / suppressions / exit decision
        |
        v
text | JSON | SARIF | HTML | JUnit
```

## Package boundaries

- `config.py` parses strict declarative settings and computes a configuration digest.
- `core/discovery.py` applies ignore, size, binary, and path-confinement rules.
- `core/git.py` validates refs and turns staged, diff, commit, or history patches into added lines.
- `core/scanner.py` orchestrates rules, stable sorting, stats, and cache use.
- `core/masking.py`, `entropy.py`, and `fingerprint.py` hold small security-critical primitives.
- `rules/` contains metadata and explainable detectors without I/O side effects.
- `policy.py` applies suppressions, baseline state, severity/confidence thresholds, and exit codes.
- `reporters/` serialize a completed result and never perform detection.
- `ui/` serves only a generated HTML report on loopback.

Dependency advisory lookup is the only optional network adapter. It lives outside generic rule
evaluation and is invoked only by an explicit online command.

## Data invariants

Paths are stored root-relative and output ordering is deterministic. Rule IDs and fingerprints are
stable compatibility identifiers. A `Finding.evidence` value is masked before it reaches policy,
cache, or reporters. Errors and incomplete work remain separate from findings so a reporter cannot
mistake missing coverage for a clean result.

## Extension points

Built-in rules register typed metadata and detector functions. Reporters implement one format over
the shared result model. End-user custom rules are declarative TOML. New code extensions should
preserve the no-execution and no-network defaults and must not make reporters responsible for
security decisions.
