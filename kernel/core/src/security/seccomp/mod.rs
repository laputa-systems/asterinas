// SPDX-License-Identifier: MPL-2.0

//! Per-thread Linux seccomp modes and filters.
//!
//! Installation copies and validates a cBPF program before publishing an
//! immutable filter chain. Syscall entry evaluates a stable snapshot, and
//! fork/clone share that chain while retaining independent per-thread heads.
//!
//! Adapted from upstream Asterinas PR #4249 ("Add native seccomp support to
//! Asterinas"). The user-notification listener, `TRACE` ptrace events, and
//! audit-transport logging from that PR are not implemented:
//! - filters that can return `SECCOMP_RET_USER_NOTIF` are rejected at install
//!   time (`EINVAL`) and the action query reports `EOPNOTSUPP` for it;
//! - `SECCOMP_RET_TRACE` evaluates like Linux without a tracer attached and
//!   the syscall is rejected with `ENOSYS`;
//! - `SECCOMP_RET_LOG` allows the syscall and emits a kernel log record.

mod abi;
mod cbpf;
mod filter;
mod install;

use ostd::{arch::cpu::context::UserContext, mm::VmIo};

use self::abi::{
    MODE_FILTER, MODE_STRICT, RET_ALLOW, RET_ERRNO, RET_KILL_PROCESS, RET_KILL_THREAD, RET_LOG,
    RET_TRACE, RET_TRAP, SeccompNotifSizes,
};
pub(crate) use self::{
    abi::SeccompData,
    filter::{SeccompDecision, SeccompState, ThreadSeccompState},
};
use crate::{cpu::LinuxAbi, prelude::*};

const SET_MODE_STRICT: u32 = 0;
const SET_MODE_FILTER: u32 = 1;
const GET_ACTION_AVAIL: u32 = 2;
const GET_NOTIF_SIZES: u32 = 3;

/// Handles seccomp operations and returns their Linux ABI values.
///
/// A filter installation can report a thread ID if `TSYNC` synchronization
/// is rejected. See [`install::install_filter`].
pub(crate) fn seccomp(operation: u32, flags: u32, args_addr: Vaddr, ctx: &Context) -> Result<isize> {
    match operation {
        SET_MODE_STRICT => {
            if flags != 0 || args_addr != 0 {
                return Err(errno!(EINVAL, "invalid strict seccomp arguments"));            }
            install::install_strict(ctx).map(|()| 0)
        }
        SET_MODE_FILTER => install::install_filter(ctx, flags, args_addr),
        GET_NOTIF_SIZES => {
            if flags != 0 {
                return Err(errno!(EINVAL, "invalid seccomp query flags"));            }
            ctx.user_space().write_val(
                args_addr,
                &SeccompNotifSizes {
                    seccomp_notif: 0,
                    seccomp_notif_resp: 0,
                    seccomp_data: size_of::<SeccompData>() as u16,
                },
            )?;
            Ok(0)
        }
        GET_ACTION_AVAIL => {
            if flags != 0 {
                return Err(errno!(EINVAL, "invalid seccomp query flags"));            }
            let action: u32 = ctx.user_space().read_val(args_addr)?;
            // Only the actions implemented by this port are reported. In
            // particular, USER_NOTIF is unsupported and unknown or
            // data-carrying action values are rejected, matching Linux's
            // EOPNOTSUPP behavior.
            match action {
                RET_ALLOW | RET_ERRNO | RET_KILL_PROCESS | RET_KILL_THREAD | RET_TRAP
                | RET_TRACE | RET_LOG => Ok(0),
                _ => return Err(errno!(EOPNOTSUPP, "unsupported seccomp action")),
            }
        }
        _ => return Err(errno!(EINVAL, "unsupported seccomp operation")),
    }
}

/// Delivers a seccomp trap with the syscall's original return-register value.
///
/// A blocked or ignored SIGSYS cannot suppress the trap: like Linux's
/// `force_sig()` for seccomp traps, the thread then dies with SIGSYS instead
/// of running the handler.
pub(crate) fn trap(ctx: &Context, user_ctx: &mut UserContext, syscall_number: i32, reason: u32) {
    use crate::process::signal::{
        constants::SIGSYS, sig_action::SigAction, signals::raw::RawSignal,
    };

    let info = SeccompData::from_context(user_ctx, syscall_number).trap_info(reason);
    // The entry path presets rax to -ENOSYS on x86, so restore the syscall
    // number that the SIGSYS handler expects in the return register.
    // Reference: syscall_rollback() in Linux arch/x86/kernel/signal.c.
    user_ctx.set_syscall_ret(ctx.thread_local.orig_syscall_ret().unwrap_or(usize::MAX));

    let is_deliverable = {
        let dispositions = ctx.process.sig_dispositions().lock();
        let dispositions = dispositions.lock();
        let is_blocked = ctx.posix_thread.has_signal_blocked(SIGSYS);
        let is_ignored = matches!(dispositions.get(SIGSYS), SigAction::Ign);
        !(is_blocked || is_ignored)
    };
    if !is_deliverable {
        crate::process::posix_thread::do_seccomp_exit_thread(SIGSYS, ctx, user_ctx);
        return;
    }

    ctx.posix_thread
        .enqueue_signal(Box::new(RawSignal::new(info)));
}

/// Handles `PR_SET_SECCOMP` using the same installation path as `seccomp(2)`.
pub(crate) fn prctl_set_seccomp(mode: u64, fprog_addr: Vaddr, ctx: &Context) -> Result<()> {
    // Unlike seccomp(2), prctl ignores its filter argument for strict mode.
    if mode == MODE_STRICT as u64 {
        return install::install_strict(ctx);
    }
    if mode != MODE_FILTER as u64 {
        return Err(errno!(EINVAL, "unsupported seccomp mode"));    }
    // With zero flags, a successful installation always returns 0.
    install::install_filter(ctx, 0, fprog_addr).map(|_| ())
}
