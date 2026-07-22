# Git history scanning

IronVeil uses Git as a content source without checking out old commits or executing hooks. It
parses added lines from zero-context diffs, masks findings immediately, and attaches the source
range or commit to each result.

## Choose the smallest scope

| Command | Scope |
| --- | --- |
| `ironveil staged` | Additions currently in the index. |
| `ironveil diff origin/main...HEAD` | Added or changed lines across a range. |
| `ironveil commit SHA` | Additions introduced by one commit. |
| `ironveil history . --max-commits 500` | Additions in bounded reachable history. |

A diff scan is normally the right pull-request gate: it focuses review on newly introduced
content. A tree scan remains useful because a rename, generated file, or policy change may need
whole-file context. Use both when the risk warrants it.

## Range semantics

For `git diff`, `A..B` compares the endpoint trees (equivalent to `A B`); `A...B` compares `B`
with the merge base of the two refs and is generally appropriate for a branch review. IronVeil validates ref
characters, passes the range as one subprocess argument, disables external diff drivers, and
terminates revision options with `--`.

Fetch sufficient history in CI. A shallow checkout may not contain the merge base or older
commits:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    fetch-depth: 0
    persist-credentials: false
```

## Bound a history scan

```console
ironveil history . --max-commits 250 --branch main
ironveil history . --since 2026-01-01 --until 2026-06-30
ironveil history . --max-commits 1000 --all-branches
```

`--all-branches` scans all locally reachable refs, not every object ever stored by a remote.
Force-pushed, garbage-collected, un-fetched, fork-only, and server-retained objects may remain
outside local scope. A partial or unreadable range must not be presented as a clean full-history
result.

## Respond to a history finding

Deleting a secret from the current file does not remove it from history. Revoke or rotate it
first. Then identify clones, forks, artifacts, caches, and deployments that may retain it. If a
rewrite is required, coordinate with repository owners, follow the hosting provider's guidance,
and expect collaborators to rebase or reclone. A rewrite is disruptive and is not a substitute
for revocation.

History reports contain masked evidence, but commit hashes, paths, and locations are still
sensitive operational metadata. Restrict report retention and access.
