# Compatibility inventory (LC-04)

This directory is the self-contained output of roadmap item LC-04.
It inventories, from repository sources only:

* **syscall dispatch entries** — every `SYS_* = N => sys_*(...)` row in
  `kernel/core/src/syscall/arch/*.rs` (x86, generic, arm, riscv, loongarch
  tables), each with a status (`implemented`, `partial`, `stub`,
  `unresolvable`), its handler source, and its SCML coverage;
* **SCML entries** — syscall flag coverage parsed from
  `book/src/kernel/linux-compatibility/syscall-flag-coverage/**/*.scml`
  (`full` for `fully_covered.scml`, `constrained` otherwise);
* **stubs** — handlers that return success (or `ENOSYS`) without performing
  the requested effect, mechanically detected or pinned in
  `annotations.json`;
* **unsupported-success paths** — kernel sites where input is warned away,
  ignored, or recorded as not enforced while success is still reported
  (heuristic scan plus curated annotations);
* **conformance blocklists** — gVisor, kselftest, xfstests, LTP, and
  pjdfstest blocked cases, each with its status, source, and recorded
  reason when one exists;
* **`__asterinas__` branches** — conditional-compilation branches and
  compile-flag definitions in `test/`.

## Usage

```
python3 test/qualification/inventory/inventory.py generate   # rewrite inventory.json + inventory.md
python3 test/qualification/inventory/inventory.py check      # verify; also accepts --check
python3 -m unittest discover test/qualification/inventory    # tests (or run test_inventory.py)
```

`check` regenerates in memory and exits 1 when the committed inventory is
missing, empty, or stale, when a dispatch handler cannot be resolved, when
an annotation no longer matches the tree, or when any dispatch entry or
blocklisted case lacks a status or source. It exits 0 only on a clean
tree. Once LC-02 lands, `run.py inventory --check` is the intended entry
point and can delegate to `inventory.main(["check"])`.

## Data files

* `inventory.py` — the generator/checker (Python standard library only).
* `annotations.json` — curated input: status overrides and unsupported-success
  confirmations that mechanical scanning cannot derive, each with a reason.
  An annotation whose `match` string disappears from the tree fails `check`.
* `inventory.json`, `inventory.md` — generated output, deterministic
  (sorted, no timestamps, repo-relative paths); never edit by hand.
* `test_inventory.py` — self-checks against synthetic repository trees.

The generation is deterministic: two runs over an unchanged tree produce
byte-identical output.
