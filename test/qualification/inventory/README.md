# Compatibility inventory (LC-04)

This directory is the self-contained output of roadmap item LC-04.
It inventories, from repository sources only:

* **syscall dispatch rows** — every literal `SYS_* = N => sys_*(...)`
  row in `kernel/core/src/syscall/arch/*.rs` (x86, generic, arm, riscv,
  loongarch tables) as its own record with status, source, and evidence;
  rows grouped under one syscall name carry a `divergent_handlers` flag
  when the tables disagree on the handler;
* **SCML rules** — every invocation row of
  `book/src/kernel/linux-compatibility/syscall-flag-coverage/**/*.scml`
  as its own entry-by-entry collection (repeated rules included),
  cross-referenced to dispatch rows through an explicit, machine-readable
  alias policy (`metadata.alias_policy`, pinned in `annotations.json`);
* **stubs** — handlers that return success (or `ENOSYS`) without
  performing the requested effect, mechanically detected or pinned in
  `annotations.json`;
* **unsupported-success paths** — kernel sites where input is warned
  away, ignored, or recorded as not enforced while success is still
  reported (heuristic scan plus curated annotations);
* **conformance blocklists** — gVisor, kselftest, xfstests, LTP
  (`testcases/all.txt` commented-out cases plus `testcases/blocked/*.txt`
  lane files), and pjdfstest, with inline `# comment` suffixes and
  preceding comment blocks extracted as reasons;
* **`__asterinas__` branches** — conditional-compilation branches and
  compile-flag definitions in `test/`.

## Status semantics

Statuses are **shallow handler-resolution evidence, not
Linux-compatibility claims**; the generated `metadata.status_semantics`
says so in machine-readable form. Unsupported-success warnings anywhere
in a syscall implementation file are associated with every handler
defined there, because warnings frequently live in shared helpers (e.g.
the clone3 argument conversion in `clone.rs`); each evidence site carries
a `scope` of `handler` or `file`. Classification rests on `warn`-kind
evidence only — comment/TODO sites are recorded for transparency but
never decide a status, and heuristic output is never promoted to curated
truth; `annotations.json` holds the reviewed pins.

## Usage

```
python3 test/qualification/inventory/inventory.py generate   # rewrite inventory.json + inventory.md
python3 test/qualification/inventory/inventory.py check      # verify; also accepts --check
python3 -m unittest discover test/qualification/inventory    # tests (or run test_inventory.py)
```

Both commands fail closed: a missing scan root
(`kernel/core/src/syscall*`, the SCML directory, the conformance
directory, `test/`) or an implausibly empty dispatch, SCML, blocklist,
or branch section is a structural error — generation exits nonzero and
writes nothing, so a non-repository path can never yield a valid empty
inventory. `check` additionally exits 1 when the committed inventory is
missing, empty, or stale, when a dispatch handler cannot be resolved,
when an annotation no longer matches the tree, or when any dispatch row
or blocklisted case lacks a status or source. Once LC-02 lands,
`run.py inventory --check` is the intended entry point and can delegate
to `inventory.main(["check"])`.

## Data files

* `inventory.py` — the generator/checker (Python standard library only).
* `annotations.json` — curated input: status overrides, unsupported-success
  confirmations, and SCML/dispatch alias groups, each with a reason. An
  annotation whose `match` string disappears from the tree fails `check`.
* `inventory.json`, `inventory.md` — generated output, deterministic
  (sorted, no timestamps, repo-relative paths); never edit by hand.
* `test_inventory.py` — self-checks against synthetic repository trees.

The generation is deterministic: two runs over an unchanged tree produce
byte-identical output.
