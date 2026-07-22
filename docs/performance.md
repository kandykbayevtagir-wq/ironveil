# Performance and cache

IronVeil favors bounded, predictable work over reading an entire repository into memory. File
discovery records metadata first; content scanning limits file size, skips binary content by
default, and uses a bounded worker pool. Git modes request only added lines for the selected
scope.

## Tune a scan

```toml
[scan]
max_size_mb = 10
workers = 8
respect_gitignore = true
scan_binary = false
use_cache = true
exclude = []
```

More workers help when many small files are available and storage can sustain concurrent reads.
They do not make one large file safe. Raising `max_size_mb`, scanning ignored files, enabling
binary scanning, or selecting all history can increase memory, disk, and CPU cost substantially.
Measure with representative repositories before standardizing changes.

Reports expose files discovered, scanned and skipped; cache hits; bytes scanned; duration; and
scan rate. Do not publish benchmark numbers without the repository shape, hardware, filesystem,
Python version, rule pack, warm/cold cache state, and exact command.

## Cache design

The metadata cache is outside the scanned repository. By default it is under
`~/.cache/ironveil`; set `IRONVEIL_CACHE_DIR` to a controlled location when platform policy
requires one. Records are private to the running account where filesystem permissions are
honored.

A cache entry is tied to repository-relative path, size, modification time, content hash, rule
pack version, and configuration digest. Cached finding evidence is already masked. A mismatch is
a miss, not a partial reuse.

```console
ironveil cache stats
ironveil cache clear
```

`clear` removes only IronVeil JSON cache records from that directory. OSV responses have their
own bounded cache records. Do not share a writable cache between mutually untrusted tenants.

## Benchmarking

Run benchmarks on synthetic repositories without real credentials. Record cold and warm results
separately, verify that finding sets are identical, and include peak memory where possible. A
performance change is unacceptable if it weakens path confinement, masking, deterministic order,
or scan completeness.
