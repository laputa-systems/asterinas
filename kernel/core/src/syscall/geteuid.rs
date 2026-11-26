// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{prelude::*, process::Uid};

pub(super) fn sys_geteuid(ctx: &Context) -> Result<SyscallReturn> {
    let euid = ctx.posix_thread.credentials().euid();
    // IDs are translated into the caller's user namespace;
    // unmapped IDs show up as the overflow UID.
    let uid = ctx.thread_local.borrow_user_ns().kuid_to_uid(euid);

    Ok(SyscallReturn::Return(<Uid as Into<u32>>::into(uid) as _))
}
