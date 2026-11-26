// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::prelude::*;

pub(super) fn sys_getresgid(
    rgid_ptr: Vaddr,
    egid_ptr: Vaddr,
    sgid_ptr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!("rgid_ptr = 0x{rgid_ptr:x}, egid_ptr = 0x{egid_ptr:x}, sgid_ptr = 0x{sgid_ptr:x}");

    let credentials = ctx.posix_thread.credentials();
    let user_space = ctx.user_space();
    // IDs are translated into the caller's user namespace;
    // unmapped IDs show up as the overflow GID.
    let user_ns = ctx.thread_local.borrow_user_ns();

    let rgid = user_ns.kgid_to_gid(credentials.rgid());
    user_space.write_val(rgid_ptr, &rgid)?;

    let egid = user_ns.kgid_to_gid(credentials.egid());
    user_space.write_val(egid_ptr, &egid)?;

    let sgid = user_ns.kgid_to_gid(credentials.sgid());
    user_space.write_val(sgid_ptr, &sgid)?;

    Ok(SyscallReturn::Return(0))
}
