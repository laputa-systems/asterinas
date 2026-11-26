// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use super::TidDirOps;
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    process::{SetgroupsState, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    security::lsm::hooks as lsm_hooks,
    thread::Thread,
};

/// Represents the inode at `/proc/[pid]/task/[tid]/setgroups` (and also `/proc/[pid]/setgroups`).
///
/// Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3411>
pub(super) struct SetgroupsFileOps(TidDirOps);

impl SetgroupsFileOps {
    pub(super) fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for SetgroupsFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        let Some((_, process)) = self.0.thread_and_process() else {
            return Err(errno!(ESRCH, "the thread or the process does not exist"));
        };
        let user_ns = process.user_ns().lock().clone();
        match user_ns.setgroups_state() {
            SetgroupsState::Allow => writeln!(printer, "allow")?,
            SetgroupsState::Deny => writeln!(printer, "deny")?,
        }

        Ok(printer.bytes_written())
    }

    fn write_at(&self, offset: usize, reader: &mut VmReader) -> Result<usize> {
        let _ = offset;
        // Reference: <https://elixir.bootlin.com/linux/v6.16.9/source/fs/proc/base.c#L1446>.
        let (content, read_bytes) = reader.read_cstring_until_end(PAGE_SIZE)?;
        let content = content
            .to_str()
            .map_err(|_| errno!(EINVAL, "setgroups only accepts \"deny\" or \"allow\""))?;

        let Some((_, process)) = self.0.thread_and_process() else {
            return Err(errno!(ESRCH, "the thread or the process does not exist"));
        };
        let target_ns = process.user_ns().lock().clone();

        let current = current_thread!();
        let current_posix = current.as_posix_thread().unwrap();
        // Changing another process's `setgroups` state requires privileges.
        if !Arc::ptr_eq(&process, &current_posix.process()) {
            lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
                current_posix.process().user_ns().lock().as_ref(),
                current_posix,
                CapSet::SETGID,
            ))?;
        }

        target_ns.write_setgroups(content)?;

        Ok(read_bytes)
    }
}
