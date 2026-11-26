// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::prelude::*;

pub(super) fn sys_getresuid(
    ruid_ptr: Vaddr,
    euid_ptr: Vaddr,
    suid_ptr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!("ruid_ptr = 0x{ruid_ptr:x}, euid_ptr = 0x{euid_ptr:x}, suid_ptr = 0x{suid_ptr:x}");

    let credentials = ctx.posix_thread.credentials();
    let user_space = ctx.user_space();
    // IDs are translated into the caller's user namespace;
    // unmapped IDs show up as the overflow UID.
    let user_ns = ctx.thread_local.borrow_user_ns();

    let ruid = user_ns.kuid_to_uid(credentials.ruid());
    user_space.write_val(ruid_ptr, &ruid)?;

    let euid = user_ns.kuid_to_uid(credentials.euid());
    user_space.write_val(euid_ptr, &euid)?;

    let suid = user_ns.kuid_to_uid(credentials.suid());
    user_space.write_val(suid_ptr, &suid)?;

    Ok(SyscallReturn::Return(0))
}
