// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{Pid, pid_table, posix_thread::RobustListHead},
    thread::Tid,
};

/// Returns the robust list head pointer and head length for a thread.
///
/// This corresponds to Linux's `get_robust_list`. Userspace runtimes probe it to check for
/// robust futex support (e.g., musl's `pthread_mutexattr_setrobust` fails the attribute if this
/// call fails), so it must succeed for the current thread even when no robust mutex has been
/// used yet.
pub(super) fn sys_get_robust_list(
    pid: Pid,
    head_ptr_ptr: Vaddr,
    len_ptr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if pid.cast_signed() < 0 {
        return Err(errno!(ESRCH, "the thread does not exist"));
    }

    // Resolve the target thread's robust list head pointer.
    //
    // Only the calling thread itself may be inspected: task-local data of other threads is not
    // accessible by design. Queries for other existing threads fail with `EPERM`, matching the
    // Linux error for disallowed queries; unknown tids fail with `ESRCH`.
    let head = if pid == 0 || pid as Tid == ctx.posix_thread.tid() {
        ctx.thread_local.robust_list().borrow().clone()
    } else if pid_table::pid_table_mut().get_thread(pid as Tid).is_some() {
        return Err(errno!(EPERM, "only the calling thread may be inspected"));
    } else {
        return Err(errno!(ESRCH, "the thread does not exist"));
    };

    let user_space = ctx.user_space();
    user_space.write_val(head_ptr_ptr, &head.unwrap_or(0))?;
    user_space.write_val(len_ptr, &size_of::<RobustListHead>())?;

    Ok(SyscallReturn::Return(0))
}
