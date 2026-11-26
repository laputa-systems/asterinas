// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{prelude::*, process::posix_thread::RobustListHead};

pub(super) fn sys_set_robust_list(
    robust_list_head_ptr: Vaddr,
    len: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!(
        "robust list head ptr: 0x{:x}, len = {}",
        robust_list_head_ptr, len
    );

    if len != size_of::<RobustListHead>() {
        return Err(errno!(
            EINVAL,
            "the length is not equal to the size of the robust list head"
        ));
    }

    // Like Linux, only the head pointer (and its length) is recorded here. The head itself is
    // re-read from userspace when the thread exits, because userspace mutates the head whenever
    // robust mutexes are locked or unlocked.
    // Reference: <https://elixir.bootlin.com/linux/v6.18/source/kernel/futex/syscalls.c#L102-L115>
    debug!("robust list head ptr: 0x{:x}", robust_list_head_ptr);

    *ctx.thread_local.robust_list().borrow_mut() = Some(robust_list_head_ptr);

    Ok(SyscallReturn::Return(0))
}
