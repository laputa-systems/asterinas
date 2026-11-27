// SPDX-License-Identifier: MPL-2.0

use align_ext::AlignExt;

use super::SyscallReturn;
use crate::{
    fs::file::SyncMode, prelude::*, thread::kernel_thread::ThreadOptions, vm::vmar::VMAR_CAP_ADDR,
};

pub(super) fn sys_msync(
    addr: Vaddr,
    len: usize,
    flag: i32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let flags = MsyncFlags::from_bits(flag).ok_or_else(|| errno!(EINVAL, "invalid flags"))?;
    debug!("addr = 0x{:x}, len = {}, flags = {:?}", addr, len, flags);

    if flags.contains(MsyncFlags::MS_ASYNC | MsyncFlags::MS_SYNC) {
        return Err(errno!(
            EINVAL,
            "MS_ASYNC and MS_SYNC cannot be specified together"
        ));
    }

    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(errno!(EINVAL, "the mapping address is not aligned"));
    }
    if len == 0 {
        return Ok(SyscallReturn::Return(0));
    }
    if VMAR_CAP_ADDR.checked_sub(addr).is_none_or(|gap| gap < len) {
        // FIXME: Linux returns `ENOMEM` if `(addr + len).align_up(PAGE_SIZE)` overflows. Here, we
        // perform a stricter validation.
        return Err(errno!(ENOMEM, "the mapping range is not in userspace"));
    }
    let addr_range = addr..(addr + len).align_up(PAGE_SIZE);

    let user_space = ctx.user_space();
    let vmar = user_space.vmar();
    let query_guard = vmar.query(addr_range.clone());

    // Check if the range is fully mapped.
    if !query_guard.is_fully_mapped() {
        return Err(errno!(
            ENOMEM,
            "the range contains pages that are not mapped"
        ));
    }

    // Do nothing if not file-backed, as <https://pubs.opengroup.org/onlinepubs/9699919799/> says.
    let targets = query_guard
        .iter()
        .filter_map(|m| m.inode().cloned().map(|inode| (inode, m.file().cloned())))
        .collect::<Vec<_>>();
    let task_fn = move || {
        let mut first_error = None;
        for (inode, file) in targets {
            // TODO: Sync a necessary range instead of syncing the whole inode.
            let result = inode.sync(SyncMode::Full);
            let result = match file {
                Some(file) => file.check_writeback_error(result),
                None => result,
            };
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        first_error
    };

    // If neither MS_SYNC nor MS_ASYNC is specified, Linux defaults to MS_ASYNC behavior.
    if flags.contains(MsyncFlags::MS_SYNC) {
        if let Some(error) = task_fn() {
            return Err(error);
        }
    } else {
        ThreadOptions::new(move || {
            let _ = task_fn();
        })
        .spawn();
    }

    Ok(SyscallReturn::Return(0))
}

bitflags! {
    /// Flags for `msync`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v6.15.1/source/include/uapi/asm-generic/mman-common.h#L42>.
    #[derive(Clone, Copy, Debug)]
    struct MsyncFlags: i32 {
        /// Performs `msync` asynchronously.
        const MS_ASYNC      = 0x01;
        /// Invalidates cache so that other processes mapping the same file
        /// will immediately see the changes after this `msync` call.
        ///
        /// Should be a no-op since we use the same page cache for all processes.
        const MS_INVALIDATE = 0x02;
        /// Performs `msync` synchronously.
        const MS_SYNC       = 0x04;
    }
}
