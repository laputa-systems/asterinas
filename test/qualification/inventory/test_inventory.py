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
    SYS_FADVISE64 = 221        => sys_fadvise64(args[..4]);
    SYS_PWRITE64 = 18          => sys_pwrite64(args[..4]);
}
"""

GENERIC_TABLE = """// SPDX-License-Identifier: MPL-2.0

macro_rules! define_syscalls_with_generic_syscall_table {
    ( $( $name: ident = $num: literal => $handler: ident $args: tt );* $(;)? ) => {
        $crate::syscall::impl_syscall_nums_and_dispatch_fn! {
            SYS_RESTART_SYSCALL = 128         => sys_restart_syscall(args[..0]);
            SYS_OPENAT = 56                   => sys_openat(args[..4]);
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
"""

SCML_CONSTRAINED = """// Open a file
openat(
    dirfd, path,
    flags = O_RDONLY | O_CLOEXEC,
    mode
);
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
    (sysc / "fadvise64.rs").write_text(FADVISE_IMPL)
    (sysc / "nanosleep.rs").write_text(RESTART_IMPL)
    (sysc / "open.rs").write_text(OPENAT_IMPL)
    (sysc / "pwrite64.rs").write_text(PWRITE64_IMPL)

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
    (conf / "ltp/testcases").mkdir(parents=True)
    (conf / "ltp/testcases/all.txt").write_text(
        "#DESCRIPTION:Kernel system calls\n"
        "# abort01\n"
        "\n"
        "access02\n"
        "# this is a prose comment\n"
        "# access04\n"
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
        code = inventory.main(
            [*argv, "--repo-root", str(repo_root)]
        )
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

    def test_every_dispatch_entry_has_status_and_source(self):
        self.generate()
        inv = self.read_inventory()
        self.assertTrue(inv["syscalls"])
        for sc in inv["syscalls"]:
            self.assertIn(sc["status"], inventory.STATUS_VOCAB, sc["name"])
            self.assertTrue(sc["source"], sc["name"])
            for entry in sc["entries"]:
                self.assertTrue(entry["source"], entry)
                self.assertIn("table", entry)
                self.assertIsInstance(entry["number"], int)

    def test_every_blocklisted_case_has_status_and_source(self):
        self.generate()
        inv = self.read_inventory()
        self.assertTrue(inv["conformance_blocklists"])
        for entry in inv["conformance_blocklists"]:
            self.assertEqual(entry["status"], "blocked")
            self.assertTrue(entry["source"], entry)

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
            by_name["pwrite64"]["status"], "implemented",
            "a warning on a deliberate error path is not unsupported-success",
        )
        self.assertIn("generic", {e["table"] for e in by_name["openat"]["entries"]})

    def test_unresolvable_handler_fails_check(self):
        table = self.repo / "kernel/core/src/syscall/arch/x86.rs"
        table.write_text(
            table.read_text() + "    SYS_GHOST = 998 => sys_ghost(args[..0]);\n"
        )
        self.generate()
        inv = self.read_inventory()
        ghost = next(s for s in inv["syscalls"] if s["name"] == "ghost")
        self.assertEqual(ghost["status"], "unresolvable")
        code, _, err = run_cli(self.repo, "check")
        self.assertEqual(code, 1)
        self.assertIn("ghost", err)

    def test_stale_annotation_fails_check(self):
        self.generate()
        page_cache = self.repo / "kernel/core/src/vm/page_cache/mod.rs"
        page_cache.write_text("// SPDX-License-Identifier: MPL-2.0\nfn x() {}\n")
        code, _, err = run_cli(self.repo, "check")
        self.assertEqual(code, 1)
        self.assertIn("annotations.json", err)

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

        xfs = {e["case"] for e in by_system["xfstests"]}
        self.assertEqual(xfs, {"generic/084", "generic/226"})

        ltp = {e["case"] for e in by_system["ltp"]}
        self.assertEqual(ltp, {"abort01", "access04"})

        pj = {e["case"]: e for e in by_system["pjdfstest"]}
        self.assertEqual(set(pj), {"rename/10.t", "utimensat/06.t"})
        self.assertEqual(
            pj["rename/10.t"]["reason"],
            "coreutils/tee bug. Uncomment me after coreutils v9.12.",
        )
        self.assertIsNone(pj["utimensat/06.t"]["reason"])

    def test_asterinas_branches(self):
        self.generate()
        inv = self.read_inventory()
        branches = [
            r for r in inv["asterinas_branches"] if r["kind"] == "branch"
        ]
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
        read = next(s for s in inv["syscalls"] if s["name"] == "read")
        self.assertEqual(read["status"], "stub")
        self.assertEqual(read["status_origin"], "mechanical")

    def test_no_crash_on_empty_repo(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        code, _, err = run_cli(empty, "generate")
        self.assertEqual(code, 0, err)
        inv = json.loads(
            (empty / "test/qualification/inventory/inventory.json").read_text()
        )
        self.assertEqual(inv["syscalls"], [])
        self.assertEqual(inv["conformance_blocklists"], [])


if __name__ == "__main__":
    unittest.main()
