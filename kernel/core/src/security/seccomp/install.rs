// SPDX-License-Identifier: MPL-2.0

//! Installation of seccomp strict mode and classic BPF filters.
//!
//! Adapted from upstream Asterinas PR #4249. The notification listener
//! flags (`SECCOMP_FILTER_FLAG_NEW_LISTENER`,
//! `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`) are rejected because user
//! notification is not implemented.

use ostd::mm::VmIo;

use super::{
    abi::{RET_ACTION_FULL, RET_USER_NOTIF, SockFilter, SockFprog},
    cbpf::{MAX_INSNS, VerifiedProgram},
};
use crate::{
    prelude::*,
    process::{credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    security::lsm::hooks::{self, CapableContext},
    thread::AsThread,
};

const FILTER_FLAG_TSYNC: u32 = 1;
const FILTER_FLAG_LOG: u32 = 1 << 1;
// Opts out of additional speculation mitigation on filter installation.
// No supported architecture currently enables such a mitigation in seccomp.
const FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;
const FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;

/// Enters strict mode, serialized against filter installation and TSYNC.
pub(super) fn install_strict(ctx: &Context) -> Result<()> {
    let _tasks = ctx.process.tasks().lock();
    let state = ctx.posix_thread.seccomp_snapshot().to_strict()?;
    ctx.posix_thread.set_seccomp(state);
    Ok(())
}

/// Validates a new filter and any requested thread synchronization before publishing the policy.
///
/// Returns `Ok(0)` on successful installation. If `TSYNC` finds an incompatible
/// thread, rejects the installation and returns `Ok(tid)` for the first such
/// thread, or reports `ESRCH` if `TSYNC_ESRCH` was requested.
pub(super) fn install_filter(ctx: &Context, flags: u32, fprog_addr: Vaddr) -> Result<isize> {
    if flags & !(FILTER_FLAG_TSYNC | FILTER_FLAG_LOG | FILTER_FLAG_SPEC_ALLOW
        | FILTER_FLAG_TSYNC_ESRCH)
        != 0
    {
        return Err(errno!(EINVAL, "unsupported seccomp filter flags"));    }
    let sync_threads = flags & FILTER_FLAG_TSYNC != 0;

    let user_space = ctx.user_space();
    let fprog: SockFprog = user_space.read_val(fprog_addr)?;
    let len = fprog.len as usize;
    if len == 0 || len > MAX_INSNS {
        return Err(errno!(EINVAL, "invalid seccomp program length"));    }
    check_install_permission(ctx)?;
    if fprog.filter == 0 {
        return Err(errno!(EINVAL, "null seccomp instruction array"));    }

    let mut raw = Vec::<SockFilter>::new();
    raw.try_reserve_exact(len)
        .map_err(|_| errno!(ENOMEM, "cannot allocate seccomp program"))?;
    // Read the program one instruction at a time so a short user mapping
    // fails with EFAULT instead of over-reading into unmapped pages.
    for index in 0..len {
        let addr = (fprog.filter as Vaddr).wrapping_add(index * size_of::<SockFilter>());
        raw.push(user_space.read_val(addr)?);
    }
    reject_user_notification(&raw)?;
    let program = VerifiedProgram::new(raw)?;

    // Ordinary installs share the task-set lock, so an append cannot lose a
    // concurrent TSYNC update. User copies and verification precede all locks.
    let tasks = ctx.process.tasks().lock();
    let old_state = ctx.posix_thread.seccomp_snapshot();
    let logging = flags & FILTER_FLAG_LOG != 0;
    let new_state = old_state.append(program, logging)?;

    if sync_threads {
        for task in tasks.as_slice() {
            if task.as_thread().unwrap().is_exited() {
                continue;
            }
            let target = task.as_posix_thread().unwrap();
            if !target.seccomp_snapshot().can_sync_from(&old_state) {
                if flags & FILTER_FLAG_TSYNC_ESRCH != 0 {
                    return Err(errno!(ESRCH, "seccomp thread synchronization failed"));                }
                return Ok(target.tid() as isize);
            }
        }
    }

    // No fallible operations remain after the first policy update.
    // Exited tasks are skipped; a racing group exit only discards a policy
    // that the dying threads will never use again.
    ctx.posix_thread.set_seccomp(new_state);
    if sync_threads {
        for task in tasks.as_slice() {
            if task.as_thread().unwrap().is_exited() {
                continue;
            }
            let target = task.as_posix_thread().unwrap();
            if !core::ptr::eq(target, ctx.posix_thread) {
                target.inherit_seccomp(ctx.posix_thread);
            }
        }
    }
    Ok(0)
}

/// Rejects filters that statically return `USER_NOTIF`.
///
/// No notification listener is implemented, so such a filter could never be
/// supervised. Dynamically computed `USER_NOTIF` results are treated as fatal
/// at evaluation time instead (see [`super::filter`]).
fn reject_user_notification(raw: &[SockFilter]) -> Result<()> {
    // BPF_RET_K.
    const RET_K: u16 = 0x06;
    if raw.iter().any(|insn| {
        insn.code == RET_K && (insn.k & RET_ACTION_FULL) == RET_USER_NOTIF
    }) {
        return Err(errno!(EINVAL, "seccomp user notification is not supported"));    }
    Ok(())
}

fn check_install_permission(ctx: &Context) -> Result<()> {
    if ctx.posix_thread.credentials().no_new_privs() {
        return Ok(());
    }

    hooks::on_capable(CapableContext::new(
        ctx.thread_local.borrow_user_ns().as_ref(),
        ctx.posix_thread,
        CapSet::SYS_ADMIN,
    ))
    .map_err(|_| errno!(EACCES, "seccomp installation is not permitted"))
}
