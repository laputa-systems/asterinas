// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use super::{
    TidDirOps,
    uid_map::{is_privileged_in_parent, map_writer_for},
};
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    process::{credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    thread::Thread,
};

/// Represents the inode at `/proc/[pid]/task/[tid]/gid_map` (and also `/proc/[pid]/gid_map`).
pub(super) struct GidMapFileOps(TidDirOps);

impl GidMapFileOps {
    pub(super) fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3403>
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for GidMapFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        let Some((_, process)) = self.0.thread_and_process() else {
            return Err(errno!(ESRCH, "the thread or the process does not exist"));
        };
        let user_ns = process.user_ns().lock().clone();
        for (first, lower_first, count) in user_ns.gid_map_extents() {
            writeln!(printer, "{} {} {}", first, lower_first, count)?;
        }

        Ok(printer.bytes_written())
    }

    fn write_at(&self, offset: usize, reader: &mut VmReader) -> Result<usize> {
        let _ = offset;
        // Reference: <https://elixir.bootlin.com/linux/v6.16.9/source/fs/proc/base.c#L1464>.
        // The whole map must be written with a single `write` system call.
        let (content, read_bytes) = reader.read_cstring_until_end(PAGE_SIZE)?;
        let content = content
            .to_str()
            .map_err(|_| errno!(EINVAL, "the GID map must be valid UTF-8"))?;

        let Some((_, process)) = self.0.thread_and_process() else {
            return Err(errno!(ESRCH, "the thread or the process does not exist"));
        };
        let target_ns = process.user_ns().lock().clone();

        let current = current_thread!();
        let current_posix = current.as_posix_thread().unwrap();
        // Writing another process's map requires privileges; a process may
        // always write its own map (subject to the map write rules).
        if !Arc::ptr_eq(&process, &current_posix.process())
            && !is_privileged_in_parent(&target_ns, current_posix, CapSet::SETGID)
        {
            return Err(errno!(
                EPERM,
                "writing another process's GID map requires CAP_SETGID"
            ));
        }
        let writer = map_writer_for(&target_ns, current_posix, CapSet::SETGID);

        target_ns.write_gid_map(content, &writer)?;

        Ok(read_bytes)
    }
}
