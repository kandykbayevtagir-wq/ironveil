# Contributing to IronVeil

Thank you for helping make repository scanning more dependable. Small, well-tested changes are
preferred to broad detector rewrites. For substantial behavior or a new external dependency,
open a design issue first so the security and compatibility trade-offs can be discussed.

## Development setup

IronVeil supports Python 3.11–3.13. Create an isolated environment from a trusted checkout:

```console
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pre-commit install
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

Run the local checks before opening a pull request:

```console
ruff check .
ruff format --check .
mypy src
pytest
python -m build
python -m twine check dist/*
mkdocs build --strict
ironveil scan .
```

Do not weaken a test or policy merely to make a check green. Explain platform-specific skips
and keep test order independent.

## Security fixtures

Never commit a real, expired, revoked, copied, or plausibly active credential. A value copied
from documentation may still be accepted by a service. Detector tests must use purpose-built
synthetic strings and identify them as fixtures in nearby test metadata.

Tests should verify that terminal, JSON, SARIF, HTML, JUnit, exceptions, snapshots, and logs do
not expose complete matched values. When a rule needs a realistic prefix or checksum, generate
the remaining material deterministically in the test and ensure it cannot authenticate.

## Adding or changing a rule

Every built-in rule needs:

- a stable `IV-...` ID that is never reused;
- a concise name and explanation;
- category, severity, and confidence justified by likely impact and detector precision;
- remediation that tells a user what to do next;
- references when an authoritative source exists;
- positive, negative, placeholder, masking, and path-context tests.

Prefer explainable checks over one large regex. Consider boundaries, case, Unicode, generated
files, examples, entropy, and variable-name context. A precision regression needs a regression
test. Renaming an ID breaks baselines and integrations and therefore requires explicit release
notes.

## Architecture boundaries

Discovery confines files to the scan root; rules inspect bounded text; policy applies baselines
and suppressions; reporters serialize already-masked findings. Rules must not write files, make
network requests, execute a repository, or decide process exit codes. Reporters must not rerun
detection. Online dependency lookup remains an explicit adapter behind `--online`.

See [docs/architecture.md](docs/architecture.md) and [docs/writing-custom-rules.md](docs/writing-custom-rules.md).

## Pull requests

Keep commits reviewable and update documentation for user-visible changes. A pull request
should state:

- the problem and chosen behavior;
- tests performed and platforms covered;
- security and privacy impact;
- compatibility impact on rule IDs, fingerprints, schemas, or exit codes.

By contributing, you agree that your contribution is licensed under Apache-2.0 and that you
have the right to submit it. Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Vulnerability reports

Potential vulnerabilities in IronVeil itself must follow [SECURITY.md](SECURITY.md). Do not put
exploit details or unmasked findings in a public issue or pull request.
