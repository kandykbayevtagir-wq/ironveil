# Dependency scanning

Dependency scanning has two explicit modes. Offline mode analyzes repository files without
contacting a registry or advisory service. Online mode additionally asks OSV about pinned package
coordinates.

```console
ironveil dependencies .
ironveil dependencies . --online
```

## Supported inputs

The preview recognizes Python `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`, and
`Pipfile.lock`; and JavaScript `package.json`, `package-lock.json`, `npm-shrinkwrap.json`,
`yarn.lock`, and `pnpm-lock.yaml`/`.yml`.

Offline rules check for unpinned or floating versions, mutable Git references, insecure or
credential-bearing sources, suspicious package names, install lifecycle scripts, missing lockfile
integrity where the format supplies it, and mutable local or editable dependencies. IronVeil
parses these files as data. It never runs a package manager, build script, or repository code.

These checks do not calculate the complete environment-specific dependency graph. Markers,
extras, workspaces, optional groups, platform resolution, and package-manager semantics can change
what is installed.

## Explicit OSV lookup

With `--online`, IronVeil sends only this metadata for resolved coordinates:

- ecosystem (`PyPI` or `npm`);
- package name;
- exact version.

It does not send source files, paths, lockfile text, credentials, Git history, or findings. The
request uses the OSV batch API with a configured timeout and bounded retries. Responses are cached
outside the repository. If OSV is unavailable, the report contains a warning or partial-result
signal instead of presenting advisory coverage as complete.

Configure behavior explicitly:

```toml
[dependencies]
online = false
timeout_seconds = 10
retries = 1
```

OSV data is an upstream signal, not proof of safety. A package can be malicious without a CVE,
an advisory can be incomplete, and a coordinate may not be extractable. Combine results with a
locked build, provenance review, dependency review, SBOM, and ecosystem-native audit tooling.
