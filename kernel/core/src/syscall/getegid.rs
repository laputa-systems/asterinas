// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{prelude::*, process::Gid};

pub(super) fn sys_getegid(ctx: &Context) -> Result<SyscallReturn> {
    let egid = ctx.posix_thread.credentials().egid();
    // IDs are translated into the caller's user namespace;
    // unmapped IDs show up as the overflow GID.
    let gid = ctx.thread_local.borrow_user_ns().kgid_to_gid(egid);

    Ok(SyscallReturn::Return(<Gid as Into<u32>>::into(gid) as _))
}
