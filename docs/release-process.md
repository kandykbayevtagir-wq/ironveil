# Release process

IronVeil uses Semantic Versioning. During the preview, detector precision, schemas, and command
details may evolve within `0.x`, but changes to rule IDs, fingerprints, output schemas, and exit
codes must still be called out explicitly.

## Prepare

1. Review `CHANGELOG.md`; move released entries under a version and ISO date.
2. Set the same version in package metadata and verify `ironveil --version`.
3. Run `ruff check .`, `ruff format --check .`, `mypy src`, and the full test suite on supported
   Python versions.
4. Build docs with `mkdocs build --strict`.
5. Build wheel and sdist; run `twine check` and install each artifact in a clean environment.
6. Run a self-scan and validate JSON, SARIF, HTML, and JUnit outputs using synthetic fixtures.
7. Review dependencies, pinned action SHAs, licenses, and the threat model.

## Tag and draft release

After the protected release pull request is merged and CI is green, create a signed annotated tag
whose name exactly matches the package version, for example `v0.1.0`. The tag-triggered workflow
repeats validation, builds artifacts, generates an SPDX JSON SBOM and SHA-256 checksums, and creates
a **draft** GitHub Release. It does not publish to PyPI.

Review the draft notes, wheel, sdist, SBOM, checksums, and provenance. Verify the tag signature using
the maintainer's documented signing identity. Publish the GitHub Release only after this review.

## PyPI Trusted Publishing

PyPI publishing is a separate manual workflow decision:

1. Configure a PyPI Trusted Publisher for this repository, the `release.yml` workflow, and the
   `pypi` GitHub environment.
2. Protect that environment with required reviewers and restrict version tags.
3. Select the release tag in **Run workflow** and explicitly enable `publish-pypi`.
4. Confirm the environment approval and monitor the publish job.

The job receives `id-token: write` only for OIDC and contains no API token. If the Trusted Publisher
does not exist or does not match, publication fails; maintainers must fix the configuration rather
than introduce a long-lived secret or bypass the environment.

## After release

Verify package metadata and installation from PyPI, keep the major action tag pointed at the
reviewed release commit, update Pages, and announce only capabilities that passed release
validation. Do not delete and recreate published artifacts under the same version.
