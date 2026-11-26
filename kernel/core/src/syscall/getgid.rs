// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{prelude::*, process::Gid};

pub(super) fn sys_getgid(ctx: &Context) -> Result<SyscallReturn> {
    let rgid = ctx.posix_thread.credentials().rgid();
    // IDs are translated into the caller's user namespace;
    // unmapped IDs show up as the overflow GID.
    let gid = ctx.thread_local.borrow_user_ns().kgid_to_gid(rgid);

    Ok(SyscallReturn::Return(<Gid as Into<u32>>::into(gid) as _))
}
