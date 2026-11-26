# SPDX-License-Identifier: MPL-2.0
"""Tests for the LC-04 inventory generator.

Each test builds a synthetic repository in a temporary directory and runs
the inventory CLI against it through `main()` with `--repo-root`, so no
test touches the real checkout. Run with:

    python3 -m unittest test_inventory -v
"""

import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import inventory

X86_TABLE = """// SPDX-License-Identifier: MPL-2.0

use super::read::sys_read;

impl_syscall_nums_and_dispatch_fn! {
    SYS_READ = 0               => sys_read(args[..3]);
    SYS_WRITE = 1              => sys_write(args[..3]);
    SYS_PWRITE64 = 18          => sys_pwrite64(args[..4]);
    SYS_CLONE3 = 435           => sys_clone3(args[..2], &mut user_ctx);
    SYS_PERSONALITY = 135      => sys_personality(args[..1]);
    SYS_GET_PRIORITY = 140     => sys_get_priority(args[..2]);
    SYS_FADVISE64 = 221        => sys_fadvise64(args[..4]);
}
"""

GENERIC_TABLE = """// SPDX-License-Identifier: MPL-2.0

macro_rules! define_syscalls_with_generic_syscall_table {
    ( $( $name: ident = $num: literal => $handler: ident $args: tt );* $(;)? ) => {
        $crate::syscall::impl_syscall_nums_and_dispatch_fn! {
            SYS_OPENAT = 56                   => sys_openat(args[..4]);
            SYS_RESTART_SYSCALL = 128         => sys_restart_syscall(args[..0]);
        }
    }
}
"""

READ_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_read(
    fd: i32,
    buf: usize,
    len: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let data = do_read(fd, buf, len, ctx)?;
    Ok(SyscallReturn::Return(data as _))
}
"""

WRITE_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_write(
    fd: i32,
    buf: usize,
    len: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    warn!("writes to fd 9 are ignored");
    let data = do_write(fd, buf, len, ctx)?;
    Ok(SyscallReturn::Return(data as _))
}
"""

PWRITE64_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_pwrite64(
    fd: i32,
    buf: usize,
    len: usize,
    offset: u64,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let file = get_file(fd, ctx).map_err(|_| {
        warn!("writes to this file type are not supported");
        errno!(EINVAL, "unsupported file type")
    })?;
    do_pwrite(file, buf, len, offset)
}
"""

# Mirrors kernel/core/src/syscall/clone.rs: the unsupported-success
# warnings live in the TryFrom<Clone3Args> conversion helper, outside the
# sys_clone3 handler body proper.
CLONE_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_clone3(
    args: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let clone3_args = Clone3Args::new(args)?;
    let clone_args = CloneArgs::try_from(clone3_args)?;
    do_clone(clone_args, ctx)
}

impl TryFrom<Clone3Args> for CloneArgs {
    type Error = Error;

    fn try_from(value: Clone3Args) -> Result<Self> {
        if value.set_tid != 0 {
            warn!("set_tid is not supported");
        }
        if value.cgroup != 0 {
            warn!("cgroup is not supported");
        }
        Ok(Self::default())
    }
}
"""

# Mirrors kernel/core/src/syscall/personality.rs: the warning uses the
# "accepted, but still does not" wording inside the handler body.
PERSONALITY_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_personality(
    personality: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if Personality::from_bits_truncate(personality).contains(Personality::ADDR_NO_RANDOMIZE) {
        warn!("`personality(ADDR_NO_RANDOMIZE)` is accepted, but still does not disable ASLR");
    }
    ctx.posix_thread.set_personality(personality);
    Ok(SyscallReturn::Return(0))
}
"""

GET_PRIORITY_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_get_priority(
    which: i32,
    who: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    do_get_priority(which, who, ctx)
}
"""

FADVISE_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_fadvise64(
    raw_fd: i32,
    offset: usize,
    len: usize,
    advice: i32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    match advice {
        0 => {
            warn!("POSIX_FADV_NORMAL is ignored");
        }
        _ => {
            warn!("POSIX_FADV_RANDOM is ignored");
        }
    }
    Ok(SyscallReturn::Return(0))
}
"""

RESTART_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_restart_syscall(ctx: &Context) -> Result<SyscallReturn> {
    do_restart(ctx)
}
"""

OPENAT_IMPL = """// SPDX-License-Identifier: MPL-2.0

use crate::prelude::*;

pub(super) fn sys_openat(
    dirfd: i32,
    path: usize,
    flags: u32,
    mode: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    do_open(dirfd, path, flags, mode, ctx)
}
"""

SCML_FULL = """// Get filesystem statistics
statfs(path, buf);

// Read a file
read(fd, buf, count);

// Get the scheduling priority
getpriority(which, who);
"""

# Two invocation rows for the same syscall: SCML repeats rules per flag
# pattern, and every row must be inventoried.
SCML_CONSTRAINED = """// Open a file relative to a directory
openat(
    dirfd, path,
    flags = O_RDONLY | O_CLOEXEC,
    mode
);

// Open a file for writing
openat(
    dirfd, path,
    flags = O_WRONLY | O_CREAT,
    mode
);

// A rule for a syscall with no dispatch row at all
undispatched_scml_only_call(fd);
"""

ANNOTATIONS = json.dumps(
    {
        "syscalls": {
            "fadvise64": {
                "status": "stub",
                "reason": "every advice variant is ignored and success is always returned",
            }
        },
        "unsupported_success_paths": [
            {
                "path": "kernel/core/src/vm/page_cache/mod.rs",
                "match": "Record the writeback error",
                "reason": "writeback errors are dropped",
            }
        ],
        "aliases": [["getpriority", "get_priority"]],
    }
)

PAGE_CACHE = """// SPDX-License-Identifier: MPL-2.0

fn complete_write_page() {
    if failed {
        // TODO: Record the writeback error (e.g., EIO) in the VMO
        // so that a subsequent sync syscall can detect it.
        ostd::error!("writeback I/O failed");
    }
}
"""

CGROUP = """// SPDX-License-Identifier: MPL-2.0

fn write_weight() {
    // TODO: Enforce cgroup CPU weight for scheduling and remove this warning.
    warn!(
        "`cpu.weight` is accepted but not enforced yet; weight = {}",
        weight
    );
}
"""


def build_repo(root):
    """Create a synthetic repository tree under `root`."""
    arch = root / "kernel/core/src/syscall/arch"
    arch.mkdir(parents=True)
    (arch / "x86.rs").write_text(X86_TABLE)
    (arch / "generic.rs").write_text(GENERIC_TABLE)
    (arch / "riscv.rs").write_text(
        "// SPDX-License-Identifier: MPL-2.0\n\n"
        "generic::define_syscalls_with_generic_syscall_table! {\n}\n"
    )

    sysc = root / "kernel/core/src/syscall"
    (sysc).mkdir(parents=True, exist_ok=True)
    (sysc / "read.rs").write_text(READ_IMPL)
    (sysc / "write.rs").write_text(WRITE_IMPL)
    (sysc / "pwrite64.rs").write_text(PWRITE64_IMPL)
    (sysc / "clone.rs").write_text(CLONE_IMPL)
    (sysc / "personality.rs").write_text(PERSONALITY_IMPL)
    (sysc / "get_priority.rs").write_text(GET_PRIORITY_IMPL)
    (sysc / "fadvise64.rs").write_text(FADVISE_IMPL)
    (sysc / "nanosleep.rs").write_text(RESTART_IMPL)
    (sysc / "open.rs").write_text(OPENAT_IMPL)

    scml = root / "book/src/kernel/linux-compatibility/syscall-flag-coverage/misc"
    scml.mkdir(parents=True)
    (scml / "fully_covered.scml").write_text(SCML_FULL)
    (scml / "openat.scml").write_text(SCML_CONSTRAINED)

    (root / "kernel/core/src/vm/page_cache").mkdir(parents=True)
    (root / "kernel/core/src/vm/page_cache/mod.rs").write_text(PAGE_CACHE)
    (root / "kernel/core/src/fs/fs_impls/cgroupfs/controller").mkdir(parents=True)
    (root / "kernel/core/src/fs/fs_impls/cgroupfs/controller/cpu.rs").write_text(
        CGROUP
    )

    conf = root / "test/initramfs/src/conformance"
    (conf / "gvisor/blocklists").mkdir(parents=True)
    (conf / "gvisor/blocklists/epoll_test").write_text(
        "EpollTest.RegularFiles\n"
        "# `EpollPwait2Timeout` expects resolution we do not provide.\n"
        "EpollTest.EpollPwait2Timeout\n"
    )
    (conf / "kselftest").mkdir(parents=True)
    (conf / "kselftest/blocklists").write_text(
        "# --- exec ---\nexec:execveat\nlsm:lsm_get_self_attr_test\n"
    )
    (conf / "xfstests/ext2/run_list").mkdir(parents=True)
    (conf / "xfstests/ext2/run_list/block.list").write_text(
        "generic/084\ngeneric/226\n"
    )
    (conf / "xfstests/virtiofs/run_list").mkdir(parents=True)
    (conf / "xfstests/virtiofs/run_list/block.list").write_text(
        "generic/344\n"
        "generic/464 # Panics while expanding the page cache under concurrent writes.\n"
    )
    (conf / "ltp/testcases/blocked").mkdir(parents=True)
    (conf / "ltp/testcases/all.txt").write_text(
        "#DESCRIPTION:Kernel system calls\n"
        "# abort01\n"
        "\n"
        "access02\n"
        "# this is a prose comment\n"
        "# access04\n"
    )
    (conf / "ltp/testcases/blocked/ext2.txt").write_text(
        "renameat201\nrenameat202\n"
    )
    (conf / "ltp/testcases/blocked/aarch64.txt").write_text(
        "# The following tests will fail.\n"
        "clone10\n"
        "mmap06\n"
        "\n"
        "# linkat01 randomly fails on Ubuntu ARM GitHub runners.\n"
        "linkat01\n"
    )
    (conf / "pjdfstest/runlists").mkdir(parents=True)
    (conf / "pjdfstest/runlists/ext2.list").write_text(
        "chflags/00.t\n"
        "# rename/10.t: coreutils/tee bug. Uncomment me after coreutils v9.12.\n"
        "# utimensat/06.t\n"
    )

    regression = root / "test/initramfs/src/regression/network"
    regression.mkdir(parents=True)
    (regression / "tcp_err.c").write_text(
        "#ifndef __asterinas__\n"
        "int linux_only;\n"
        "#endif\n"
        "#ifdef __asterinas__\n"
        "int asterinas_only;\n"
        "#else\n"
        "int linux_fallback;\n"
        "#endif\n"
        "#if defined(__asterinas__) && defined(X)\n"
        "int both;\n"
        "#endif\n"
    )
    common = root / "test/initramfs/src/regression/common"
    common.mkdir(parents=True)
    (common / "Makefile").write_text("C_FLAGS += -D__asterinas__\n")

    invdir = root / "test/qualification/inventory"
    invdir.mkdir(parents=True)
    (invdir / "annotations.json").write_text(ANNOTATIONS)


def run_cli(repo_root, *argv):
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = inventory.main([*argv, "--repo-root", str(repo_root)])
    return code, out.getvalue(), err.getvalue()


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="invtest"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        build_repo(self.repo)
        self.outdir = self.repo / "test/qualification/inventory"

    def generate(self):
        code, out, err = run_cli(self.repo, "generate")
        self.assertEqual(code, 0, err)
        return out

    def read_inventory(self):
        return json.loads((self.outdir / "inventory.json").read_text())

    def rows_by_name(self, inv, name):
        return [r for r in inv["dispatch_rows"] if r["syscall"] == name]

    # -- basic generate/check lifecycle --------------------------------

    def test_generate_then_check_passes(self):
        self.generate()
        code, out, err = run_cli(self.repo, "check")
        self.assertEqual(code, 0, err)
        self.assertIn("check passed", out)

    def test_check_flag_equivalent(self):
        self.generate()
        code, _, err = run_cli(self.repo, "--check")
        self.assertEqual(code, 0, err)

    def test_missing_inventory_fails_check(self):
        code, _, err = run_cli(self.repo, "check")
        self.assertEqual(code, 1)
        self.assertIn("missing", err)

    def test_empty_inventory_fails_check(self):
        self.generate()
        (self.outdir / "inventory.json").write_text("")
        code, _, err = run_cli(self.repo, "check")
        self.assertEqual(code, 1)
        self.assertIn("empty", err)

    def test_stale_after_source_change_fails_check(self):
        self.generate()
        table = self.repo / "kernel/core/src/syscall/arch/x86.rs"
        table.write_text(
            table.read_text() + "    SYS_NINE = 999 => sys_read(args[..3]);\n"
        )
        code, _, err = run_cli(self.repo, "check")
        self.assertEqual(code, 1)
        self.assertIn("stale", err)

    def test_regeneration_is_deterministic(self):
        self.generate()
        first_json = (self.outdir / "inventory.json").read_bytes()
        first_md = (self.outdir / "inventory.md").read_bytes()
        self.generate()
        self.assertEqual(first_json, (self.outdir / "inventory.json").read_bytes())
        self.assertEqual(first_md, (self.outdir / "inventory.md").read_bytes())

    # -- fail-closed structure validation ------------------------------

    def test_non_repository_path_fails_closed(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        code, _, err = run_cli(empty, "generate")
        self.assertEqual(code, 1)
        self.assertIn("required scan root missing", err)
        self.assertFalse(
            (empty / "test/qualification/inventory/inventory.json").exists(),
            "an invalid inventory must not be written",
        )
        code, _, err = run_cli(empty, "check")
        self.assertEqual(code, 1)

    def test_missing_scan_root_fails(self):
        shutil.rmtree(self.repo / "kernel/core/src/syscall/arch")
        code, _, err = run_cli(self.repo, "generate")
        self.assertEqual(code, 1)
        self.assertIn("required scan root missing", err)
        self.assertFalse((self.outdir / "inventory.json").exists())

    def test_implausibly_empty_sections_fail(self):
        shutil.rmtree(self.repo / "test/initramfs/src/conformance/gvisor")
        shutil.rmtree(self.repo / "test/initramfs/src/conformance/kselftest")
        shutil.rmtree(self.repo / "test/initramfs/src/conformance/xfstests")
        shutil.rmtree(self.repo / "test/initramfs/src/conformance/ltp")
        shutil.rmtree(self.repo / "test/initramfs/src/conformance/pjdfstest")
        code, _, err = run_cli(self.repo, "generate")
        self.assertEqual(code, 1)
        self.assertIn("no conformance blocklisted cases found", err)

    def test_missing_scml_root_fails(self):
        shutil.rmtree(
            self.repo / "book/src/kernel/linux-compatibility/syscall-flag-coverage"
        )
        code, _, err = run_cli(self.repo, "generate")
        self.assertEqual(code, 1)
        self.assertIn("required scan root missing", err)

    # -- dispatch rows --------------------------------------------------

    def test_every_dispatch_row_has_status_and_source(self):
        self.generate()
        inv = self.read_inventory()
        self.assertTrue(inv["dispatch_rows"])
        for row in inv["dispatch_rows"]:
            self.assertIn(row["status"], inventory.STATUS_VOCAB, row)
            self.assertTrue(row["source"], row)
            self.assertTrue(row["handler_source"], row)
            self.assertIn("table", row)
            self.assertIsInstance(row["number"], int)
            self.assertIn("divergent_handlers", row)

    def test_rows_grouped_under_one_syscall(self):
        self.generate()
        inv = self.read_inventory()
        openat_rows = self.rows_by_name(inv, "openat")
        self.assertEqual(len(openat_rows), 1)
        self.assertEqual(openat_rows[0]["table"], "generic")
        read_rows = self.rows_by_name(inv, "read")
        self.assertEqual(len(read_rows), 1)
        self.assertEqual(read_rows[0]["number"], 0)
        group = next(s for s in inv["syscalls"] if s["name"] == "read")
        self.assertFalse(group["divergent_handlers"])

    def test_divergent_handlers_detected(self):
        generic = self.repo / "kernel/core/src/syscall/arch/generic.rs"
        generic.write_text(
            generic.read_text().replace(
                "SYS_OPENAT = 56                   => sys_openat(args[..4]);",
                "SYS_READ = 63                     => sys_restart_syscall(args[..0]);\n"
                "            SYS_OPENAT = 56                   => sys_openat(args[..4]);",
            )
        )
        self.generate()
        inv = self.read_inventory()
        group = next(s for s in inv["syscalls"] if s["name"] == "read")
        self.assertTrue(group["divergent_handlers"])
        self.assertEqual(
            group["handlers"], ["sys_read", "sys_restart_syscall"]
        )
        rows = self.rows_by_name(inv, "read")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["divergent_handlers"] for r in rows))

    def test_unresolvable_handler_fails_check(self):
        table = self.repo / "kernel/core/src/syscall/arch/x86.rs"
        table.write_text(
            table.read_text() + "    SYS_GHOST = 998 => sys_ghost(args[..0]);\n"
        )
        self.generate()
        inv = self.read_inventory()
        ghost = self.rows_by_name(inv, "ghost")[0]
        self.assertEqual(ghost["status"], "unresolvable")
        self.assertIsNone(ghost["handler_source"])
        code, _, err = run_cli(self.repo, "check")
        self.assertEqual(code, 1)
        self.assertIn("ghost", err)

    # -- status classification ------------------------------------------

    def test_classification(self):
        self.generate()
        inv = self.read_inventory()
        by_name = {s["name"]: s for s in inv["syscalls"]}
        self.assertEqual(by_name["read"]["status"], "implemented")
        self.assertEqual(by_name["read"]["scml"]["coverage"], "full")
        self.assertEqual(by_name["write"]["status"], "partial")
        self.assertEqual(by_name["write"]["status_origin"], "mechanical")
        self.assertEqual(by_name["fadvise64"]["status"], "stub")
        self.assertEqual(by_name["fadvise64"]["status_origin"], "annotations.json")
        self.assertEqual(by_name["openat"]["scml"]["coverage"], "constrained")
        self.assertEqual(by_name["restart_syscall"]["scml"]["coverage"], "absent")
        self.assertEqual(
            by_name["pwrite64"]["status"],
            "implemented",
            "a warning on a deliberate error path is not unsupported-success",
        )

    def test_file_scope_evidence_associated_with_handler(self):
        """clone3-style regression: warnings in a conversion helper outside
        the handler body still classify the syscall as partial, with the
        evidence scoped as file-level."""
        self.generate()
        inv = self.read_inventory()
        row = self.rows_by_name(inv, "clone3")[0]
        self.assertEqual(row["status"], "partial")
        self.assertEqual(len(row["evidence"]), 2)
        self.assertTrue(all(e["scope"] == "file" for e in row["evidence"]))
        lines = sorted(e["line"] for e in row["evidence"])
        self.assertEqual(lines, [19, 22])

    def test_accepted_but_keyword_classifies_partial(self):
        """personality-style regression: `accepted, but still does not`
        wording inside the handler body is unsupported-success evidence."""
        self.generate()
        inv = self.read_inventory()
        row = self.rows_by_name(inv, "personality")[0]
        self.assertEqual(row["status"], "partial")
        self.assertEqual(len(row["evidence"]), 1)
        self.assertEqual(row["evidence"][0]["scope"], "handler")
        self.assertIn("does not disable ASLR", row["evidence"][0]["snippet"])

    def test_enosys_only_handler_is_stub(self):
        sysc = self.repo / "kernel/core/src/syscall"
        (sysc / "read.rs").write_text(
            "// SPDX-License-Identifier: MPL-2.0\n"
            "use crate::prelude::*;\n"
            "pub(super) fn sys_read(ctx: &Context) -> Result<SyscallReturn> {\n"
            '    Err(errno!(ENOSYS, "not implemented"))\n'
            "}\n"
        )
        self.generate()
        inv = self.read_inventory()
        read = self.rows_by_name(inv, "read")[0]
        self.assertEqual(read["status"], "stub")
        self.assertEqual(read["status_origin"], "mechanical")

    def test_status_semantics_in_metadata(self):
        self.generate()
        inv = self.read_inventory()
        meta = inv["metadata"]
        for status in inventory.STATUS_VOCAB:
            self.assertIn(status, meta["status_semantics"])
        self.assertIn(
            "shallow", meta["status_semantics"]["implemented"]
        )
        self.assertIn("alias", json.dumps(meta["alias_policy"]))
        self.assertEqual(meta["alias_policy"]["groups"], [["getpriority", "get_priority"]])
        self.assertIn("evidence_association", meta)

    # -- SCML -------------------------------------------------------------

    def test_scml_rules_are_entry_by_entry(self):
        self.generate()
        inv = self.read_inventory()
        rules = inv["scml_rules"]
        # SCML_FULL has 3 rows, SCML_CONSTRAINED has 3 rows.
        self.assertEqual(len(rules), 6)
        openat_rules = [r for r in rules if r["name"] == "openat"]
        self.assertEqual(
            len(openat_rules), 2, "repeated rules must each be inventoried"
        )
        self.assertNotEqual(openat_rules[0]["source"], openat_rules[1]["source"])
        for rule in rules:
            self.assertTrue(rule["source"])
            self.assertIn("dispatched", rule)

    def test_scml_only_names_marked_undispatched(self):
        self.generate()
        inv = self.read_inventory()
        only = next(
            r for r in inv["scml_rules"] if r["name"] == "undispatched_scml_only_call"
        )
        self.assertFalse(only["dispatched"])
        self.assertEqual(only["dispatch_names"], [])

    def test_alias_policy_applied(self):
        self.generate()
        inv = self.read_inventory()
        row = self.rows_by_name(inv, "get_priority")[0]
        self.assertEqual(row["scml"]["coverage"], "full")
        self.assertEqual(row["scml"]["scml_name"], "getpriority")
        self.assertTrue(row["scml"]["via_alias"])
        rule = next(r for r in inv["scml_rules"] if r["name"] == "getpriority")
        self.assertTrue(rule["dispatched"])
        self.assertEqual(rule["dispatch_names"], ["get_priority"])
        self.assertTrue(rule["via_alias"])

    def test_absent_coverage_when_no_alias_exists(self):
        self.generate()
        inv = self.read_inventory()
        row = self.rows_by_name(inv, "restart_syscall")[0]
        self.assertEqual(row["scml"]["coverage"], "absent")
        self.assertIsNone(row["scml"]["source"])

    # -- annotations ------------------------------------------------------

    def test_stale_annotation_fails_check(self):
        self.generate()
        page_cache = self.repo / "kernel/core/src/vm/page_cache/mod.rs"
        page_cache.write_text("// SPDX-License-Identifier: MPL-2.0\nfn x() {}\n")
        code, _, err = run_cli(self.repo, "check")
        self.assertEqual(code, 1)
        self.assertIn("annotations.json", err)

    # -- blocklists ---------------------------------------------------------

    def test_every_blocklisted_case_has_status_and_source(self):
        self.generate()
        inv = self.read_inventory()
        self.assertTrue(inv["conformance_blocklists"])
        for entry in inv["conformance_blocklists"]:
            self.assertEqual(entry["status"], "blocked")
            self.assertTrue(entry["source"], entry)

    def test_blocklist_extraction(self):
        self.generate()
        inv = self.read_inventory()
        entries = inv["conformance_blocklists"]
        by_system = {}
        for e in entries:
            by_system.setdefault(e["system"], []).append(e)

        gvisor = {e["case"]: e for e in by_system["gvisor"]}
        self.assertIn("EpollTest.RegularFiles", gvisor)
        self.assertEqual(
            gvisor["EpollTest.EpollPwait2Timeout"]["reason"],
            "`EpollPwait2Timeout` expects resolution we do not provide.",
        )
        self.assertIsNone(gvisor["EpollTest.RegularFiles"]["reason"])

        kself = {e["case"] for e in by_system["kselftest"]}
        self.assertEqual(kself, {"exec:execveat", "lsm:lsm_get_self_attr_test"})

        pj = {e["case"]: e for e in by_system["pjdfstest"]}
        self.assertEqual(set(pj), {"rename/10.t", "utimensat/06.t"})
        self.assertEqual(
            pj["rename/10.t"]["reason"],
            "coreutils/tee bug. Uncomment me after coreutils v9.12.",
        )
        self.assertIsNone(pj["utimensat/06.t"]["reason"])

    def test_xfstests_inline_comment_is_reason(self):
        self.generate()
        inv = self.read_inventory()
        entries = [
            e
            for e in inv["conformance_blocklists"]
            if e["system"] == "xfstests" and e["case"] == "generic/464"
        ]
        self.assertEqual(len(entries), 1)
        self.assertEqual(
            entries[0]["reason"],
            "Panics while expanding the page cache under concurrent writes.",
        )
        plain = next(
            e
            for e in inv["conformance_blocklists"]
            if e["system"] == "xfstests" and e["case"] == "generic/344"
        )
        self.assertIsNone(plain["reason"])

    def test_ltp_blocked_files_included(self):
        self.generate()
        inv = self.read_inventory()
        ltp = [e for e in inv["conformance_blocklists"] if e["system"] == "ltp"]
        suites = {}
        for e in ltp:
            suites.setdefault(e["suite"], []).append(e)
        self.assertEqual({e["case"] for e in suites["all.txt"]}, {"abort01", "access04"})
        self.assertEqual(
            {e["case"] for e in suites["blocked/ext2.txt"]},
            {"renameat201", "renameat202"},
        )
        aarch64 = {e["case"]: e for e in suites["blocked/aarch64.txt"]}
        self.assertEqual(set(aarch64), {"clone10", "mmap06", "linkat01"})
        self.assertEqual(
            aarch64["clone10"]["reason"], "The following tests will fail."
        )
        self.assertEqual(
            aarch64["linkat01"]["reason"],
            "linkat01 randomly fails on Ubuntu ARM GitHub runners.",
        )

    def test_omitted_ltp_blocked_input_detected(self):
        self.generate()
        first = (self.outdir / "inventory.json").read_text()
        self.assertIn("blocked/aarch64.txt", first)
        (self.repo / "test/initramfs/src/conformance/ltp/testcases/blocked/aarch64.txt").unlink()
        code, _, err = run_cli(self.repo, "check")
        self.assertEqual(code, 1)
        self.assertIn("stale", err)
        self.generate()
        second = (self.outdir / "inventory.json").read_text()
        self.assertNotIn("blocked/aarch64.txt", second)
        self.assertIn("blocked/ext2.txt", second)

    # -- branches and unsupported-success scan ------------------------------

    def test_asterinas_branches(self):
        self.generate()
        inv = self.read_inventory()
        branches = [r for r in inv["asterinas_branches"] if r["kind"] == "branch"]
        c_file = "test/initramfs/src/regression/network/tcp_err.c"
        mine = [r for r in branches if r["path"] == c_file]
        self.assertEqual(len(mine), 3)
        self.assertEqual(mine[0]["directive"], "ifndef")
        self.assertEqual(mine[0]["polarity"], "negative")
        self.assertEqual(mine[1]["directive"], "ifdef")
        self.assertEqual(mine[1]["polarity"], "positive")
        self.assertEqual(mine[2]["directive"], "if")
        definitions = [
            r for r in inv["asterinas_branches"] if r["kind"] == "definition"
        ]
        self.assertEqual(len(definitions), 1)
        self.assertTrue(definitions[0]["path"].endswith("Makefile"))

    def test_unsupported_success_scan(self):
        self.generate()
        inv = self.read_inventory()
        paths = inv["unsupported_success_paths"]
        cgroup = [p for p in paths if "cgroupfs" in p["path"]]
        self.assertTrue(any(p["kind"] == "warn" for p in cgroup))
        self.assertTrue(any(p["kind"] == "todo" for p in cgroup))
        annotated = [p for p in paths if p["kind"] == "annotation"]
        self.assertEqual(len(annotated), 1)
        self.assertIn("writeback errors are dropped", annotated[0]["snippet"])
        for p in paths:
            self.assertTrue(p["source"])

    def test_comment_noise_not_promoted_to_syscall_status(self):
        """A heuristic comment-kind site in a file does not by itself mark
        a syscall partial; only warn evidence does."""
        sysc = self.repo / "kernel/core/src/syscall"
        (sysc / "read.rs").write_text(
            "// SPDX-License-Identifier: MPL-2.0\n"
            "use crate::prelude::*;\n"
            "// Absent names are ignored.\n"
            "pub(super) fn sys_read(ctx: &Context) -> Result<SyscallReturn> {\n"
            "    do_read(ctx)\n"
            "}\n"
        )
        self.generate()
        inv = self.read_inventory()
        row = self.rows_by_name(inv, "read")[0]
        self.assertEqual(row["status"], "implemented")
        self.assertTrue(
            all(e["kind"] != "warn" for e in row["evidence"]),
            "comment-kind sites may be recorded as evidence but must not classify",
        )


if __name__ == "__main__":
    unittest.main()
