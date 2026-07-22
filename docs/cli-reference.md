# CLI reference

`ironveil` and `python -m ironveil` expose the same interface. Run `ironveil COMMAND --help`
for the exact options in the installed version.

## Global behavior

`ironveil PATH` is equivalent to `ironveil scan PATH`. Paths default to the current directory
where a command accepts one. Common scan options include:

| Option | Purpose |
| --- | --- |
| `--config PATH` | Load an explicit TOML file instead of `ROOT/.ironveil.toml`. |
| `--format text\|json\|sarif\|html\|junit` | Select one reporter. |
| `--output PATH` | Write the selected report to a file. |
| `--fail-severity LEVEL` | Lowest severity that may fail policy. |
| `--minimum-confidence LEVEL` | Lowest confidence included in policy. |
| `--fail-on LIST` | Comma-separated categories that may fail policy. |
| `--no-fail` | Do not return `1` for policy findings. |
| `--no-color` | Disable terminal color even when output is a TTY. |

Severity values are `critical`, `high`, `medium`, `low`, and `info`. Confidence values are
`high`, `medium`, and `low`. Categories include `secret`, `sensitive-file`, `dependency`,
`iac`, `repository`, and `scan-error`.

## Scan commands

### `scan [PATH]`

Scan the current filesystem view. By default discovery respects `.gitignore` and confines
resolved paths to the root. `--tracked-only` narrows discovery to Git-tracked files;
`--all-files` includes ignored files and generated directories. Use the latter deliberately.

### `staged`

Scan added lines in the Git index. This is the fast path used by the pre-commit integration.
Deleted lines are not treated as current exposure, and the full matched value is not printed.

### `pre-commit`

Run the staged policy with hook-oriented output and exit codes. It is normally invoked by
`.pre-commit-hooks.yaml` or the managed Git hook.

### `diff RANGE`

Scan added lines in a validated Git range, for example `origin/main...HEAD`. Quote a range if
the calling shell treats any character specially.

### `commit SHA`

Scan additions introduced by one commit. The ref is resolved to a commit before content is
read.

### `history [PATH]`

Scan additions from bounded reachable history. Options include `--max-commits`, `--since`,
`--until`, `--branch`, and `--all-branches`. See [Git history scanning](git-history.md).

## Policy and lifecycle commands

### `baseline create|update|verify [PATH]`

Create, intentionally replace, or verify `.ironveil-baseline.json`. See [Baselines](baseline.md).

### `dependencies [PATH]`

Inspect supported Python and JavaScript dependency files offline. `--online` additionally sends
package coordinates to OSV. See [Dependency scanning](dependency-scanning.md).

### `ui [PATH]`

Scan, render HTML, and serve it on `127.0.0.1`. Options include `--port`, `--no-open`,
`--history`, and `--diff RANGE`.

### `init`

Create `.ironveil.toml` without overwriting an existing file.

### `doctor`

Check the runtime, Git, configuration, report destination, online dependency availability, and
suppression status. It does not change scanner configuration.

### `install-hook`

Install IronVeil's managed Git pre-commit hook. An existing non-IronVeil hook is never silently
overwritten. `--backup-existing` explicitly preserves it as a backup before replacement.

### `cache stats|clear`

Show external cache size and entry count, or remove only IronVeil cache records. See
[Performance and cache](performance.md).

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Completed and policy passed. |
| `1` | Policy-violating findings were detected. |
| `2` | Configuration or execution error. |
| `3` | Partial scan; completeness is materially reduced. |
