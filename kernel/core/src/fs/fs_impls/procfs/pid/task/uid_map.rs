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
    process::{
        MapWriter, UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread,
    },
    security::lsm::hooks as lsm_hooks,
    thread::Thread,
};

/// Represents the inode at `/proc/[pid]/task/[tid]/uid_map` (and also `/proc/[pid]/uid_map`).
pub(super) struct UidMapFileOps(TidDirOps);

impl UidMapFileOps {
    pub(super) fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3402>
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for UidMapFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        let Some((_, process)) = self.0.thread_and_process() else {
            return Err(errno!(ESRCH, "the thread or the process does not exist"));
        };
        let user_ns = process.user_ns().lock().clone();
        for (first, lower_first, count) in user_ns.uid_map_extents() {
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
            .map_err(|_| errno!(EINVAL, "the UID map must be valid UTF-8"))?;

        let Some((_, process)) = self.0.thread_and_process() else {
            return Err(errno!(ESRCH, "the thread or the process does not exist"));
        };
        let target_ns = process.user_ns().lock().clone();

        let current = current_thread!();
        let current_posix = current.as_posix_thread().unwrap();
        // Writing another process's map requires privileges; a process may
        // always write its own map (subject to the map write rules).
        if !Arc::ptr_eq(&process, &current_posix.process())
            && !is_privileged_in_parent(&target_ns, current_posix, CapSet::SETUID)
        {
            return Err(errno!(
                EPERM,
                "writing another process's UID map requires CAP_SETUID"
            ));
        }
        let writer = map_writer_for(&target_ns, current_posix, CapSet::SETUID);

        target_ns.write_uid_map(content, &writer)?;

        Ok(read_bytes)
    }
}

/// Returns whether `thread` has `cap` in the parent of `target_ns`.
pub(super) fn is_privileged_in_parent(
    target_ns: &Arc<UserNamespace>,
    thread: &crate::process::posix_thread::PosixThread,
    cap: CapSet,
) -> bool {
    let parent_ns = target_ns
        .parent_ns()
        .unwrap_or_else(|| UserNamespace::get_init_singleton().clone());
    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        parent_ns.as_ref(),
        thread,
        cap,
    ))
    .is_ok()
}

/// Collects the [`MapWriter`] info for `thread` writing a map of `target_ns`.
pub(super) fn map_writer_for(
    target_ns: &Arc<UserNamespace>,
    thread: &crate::process::posix_thread::PosixThread,
    cap: CapSet,
) -> MapWriter {
    let credentials = thread.credentials();
    MapWriter {
        euid: credentials.euid(),
        egid: credentials.egid(),
        groups: credentials.groups().clone(),
        privileged: is_privileged_in_parent(target_ns, thread, cap),
    }
}
