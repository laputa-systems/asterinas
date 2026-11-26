// SPDX-License-Identifier: MPL-2.0

//! This module implements the `setns` syscall.
//!
//! This syscall reassociates the calling thread with a namespace specified by a
//! file descriptor. The `flags` argument determines which type of namespace can be
//! joined.
//!
//! The file descriptor `fd` can refer to:
//! 1. A namespace file from `/proc/[pid]/ns/`.
//! 2. A `PidFile` opened by `pidfd_open` or by opening `/proc/[pid]` directory.

use crate::{
    fs::{
        cgroupfs::CgroupNamespace,
        file::{FileLike, InodeHandle, file_table::RawFileDesc},
        pseudofs::{NsCommonOps, NsFile},
        vfs::path::MountNamespace,
    },
    ipc::IpcNamespace,
    net::uts_ns::UtsNamespace,
    prelude::*,
    process::{
        CloneFlags, ContextSetNsAdminApi, NsProxy, NsProxyBuilder, PidFile, PidNamespace,
        PidNsForChildren, PidNsState, check_unsupported_ns_flags,
        credentials::capabilities::CapSet, posix_thread::AsPosixThread,
    },
    security::lsm::hooks as lsm_hooks,
    syscall::SyscallReturn,
};

pub(super) fn sys_setns(fd: RawFileDesc, flags: u32, ctx: &Context) -> Result<SyscallReturn> {
    let ns_type_flags =
        CloneFlags::from_bits(flags).ok_or_else(|| errno!(EINVAL, "invalid `setns` flags"))?;
    debug!("setns flags = {:?}", ns_type_flags);

    let file = {
        let file_table = ctx.thread_local.borrow_file_table();
        let file_table_locked = file_table.read();
        file_table_locked.get_file(fd.try_into()?)?.clone()
    };

    let (new_ns_proxy, pid_ns_target) = if let Some(pid_file) = file.downcast_ref::<PidFile>() {
        build_proxy_from_pid_file(pid_file, ns_type_flags, ctx)?
    } else {
        build_proxy_from_ns_file(file.as_ref(), ns_type_flags, ctx)?
    };

    if let Some(new_ns_proxy) = new_ns_proxy {
        // Install the newly created `NsProxy`.
        ctx.set_ns_proxy(Arc::new(new_ns_proxy));
    }

    if let Some(target_pid_ns) = pid_ns_target {
        set_pid_ns_for_children(target_pid_ns, ctx)?;
    }

    Ok(SyscallReturn::Return(0))
}

fn build_proxy_from_pid_file(
    pid_file: &PidFile,
    flags: CloneFlags,
    ctx: &Context,
) -> Result<(Option<NsProxy>, Option<Arc<PidNamespace>>)> {
    if flags.is_empty() {
        return Err(errno!(EINVAL, "flags must be specified with a PID file"));
    }

    // Check for any flags that are not namespace-related.
    if !(flags - CloneFlags::CLONE_NS_FLAGS).is_empty() {
        return Err(errno!(
            EINVAL,
            "invalid flags are specified with a PID file"
        ));
    }

    if flags.contains(CloneFlags::CLONE_NEWUSER) {
        return Err(errno!(EINVAL, "setting a user namespace is not supported"));
    }

    let mut remaining_flags = flags;
    let mut pid_ns_target = None;

    let target_thread = pid_file
        .process_opt()
        .ok_or_else(|| errno!(ESRCH, "the target process has been reaped"))?
        .main_thread();
    let target_proxy = target_thread.as_posix_thread().unwrap().ns_proxy().lock();
    let Some(target_proxy) = target_proxy.as_ref() else {
        return Err(errno!(ESRCH, "the target process has exited"));
    };

    let current_proxy = ctx.thread_local.borrow_ns_proxy();
    let mut builder = NsProxyBuilder::new(&current_proxy);

    if remaining_flags.contains(CloneFlags::CLONE_NEWPID) {
        pid_ns_target = Some(
            pid_file
                .process_opt()
                .ok_or_else(|| errno!(ESRCH, "the target process has been reaped"))?
                .active_pid_ns()
                .clone(),
        );
        remaining_flags.remove(CloneFlags::CLONE_NEWPID);
    }

    check_unsupported_ns_flags(remaining_flags)?;

    if flags.contains(CloneFlags::CLONE_NEWCGROUP) {
        let target_ns = target_proxy.cgroup_ns();
        set_cgroup_ns(&mut builder, target_ns, ctx)?;
    }

    if flags.contains(CloneFlags::CLONE_NEWIPC) {
        let target_ns = target_proxy.ipc_ns();
        set_ipc_ns(&mut builder, target_ns, ctx)?;
    }

    if flags.contains(CloneFlags::CLONE_NEWNS) {
        let target_ns = target_proxy.mnt_ns();
        set_mnt_ns(&mut builder, target_ns, ctx)?;
    }

    if flags.contains(CloneFlags::CLONE_NEWUTS) {
        let target_ns = target_proxy.uts_ns();
        set_uts_ns(&mut builder, target_ns, ctx)?;
    }

    // TODO: Support setting other namespaces from the target process.

    let proxy = if remaining_flags.is_empty() {
        None
    } else {
        Some(builder.build())
    };

    Ok((proxy, pid_ns_target))
}

fn build_proxy_from_ns_file(
    file: &dyn FileLike,
    flags: CloneFlags,
    ctx: &Context,
) -> Result<(Option<NsProxy>, Option<Arc<PidNamespace>>)> {
    if flags.contains(CloneFlags::CLONE_NEWUSER) {
        return Err(errno!(EINVAL, "setting a user namespace is not supported"));
    }

    let mut remaining_flags = flags;
    let mut pid_ns_target = None;

    let inode_handle = file
        .downcast_ref::<InodeHandle>()
        .ok_or_else(|| errno!(EINVAL, "the file is not a ns file"))?;

    let current_proxy = ctx.thread_local.borrow_ns_proxy();
    let mut builder = NsProxyBuilder::new(&current_proxy);

    if let Some(ns_file) = inode_handle.downcast_open_file::<NsFile<PidNamespace>>()? {
        if !remaining_flags.is_empty() && remaining_flags != CloneFlags::CLONE_NEWPID {
            return Err(errno!(
                EINVAL,
                "the flags do not match the type of the ns file"
            ));
        }
        pid_ns_target = Some(ns_file.ns().clone());
        remaining_flags = CloneFlags::empty();
    }

    check_unsupported_ns_flags(remaining_flags)?;

    #[expect(clippy::nonminimal_bool)]
    let applied = false
        || try_apply_ns_from_inode::<CgroupNamespace>(inode_handle, remaining_flags, |ns| {
            set_cgroup_ns(&mut builder, &ns, ctx)
        })?
        || try_apply_ns_from_inode::<IpcNamespace>(inode_handle, remaining_flags, |ns| {
            set_ipc_ns(&mut builder, &ns, ctx)
        })?
        || try_apply_ns_from_inode::<MountNamespace>(inode_handle, remaining_flags, |ns| {
            set_mnt_ns(&mut builder, &ns, ctx)
        })?
        || try_apply_ns_from_inode::<UtsNamespace>(inode_handle, remaining_flags, |ns| {
            set_uts_ns(&mut builder, &ns, ctx)
        })?;
    // TODO: Support setting other namespaces from the ns file.

    if !applied && pid_ns_target.is_none() {
        return Err(errno!(EINVAL, "invalid flags are specified with a ns file"));
    }

    let proxy = if applied { Some(builder.build()) } else { None };
    Ok((proxy, pid_ns_target))
}

fn try_apply_ns_from_inode<T: NsCommonOps>(
    inode_handle: &InodeHandle,
    flags: CloneFlags,
    apply: impl FnOnce(Arc<T>) -> Result<()>,
) -> Result<bool> {
    let Some(ns_file) = inode_handle.downcast_open_file::<NsFile<T>>()? else {
        return Ok(false);
    };

    if !flags.is_empty() && flags != T::TYPE.into() {
        return Err(errno!(
            EINVAL,
            "the flags do not match the type of the ns file"
        ));
    }

    apply(ns_file.ns().clone())?;
    Ok(true)
}

fn set_cgroup_ns(
    builder: &mut NsProxyBuilder,
    target_ns: &Arc<CgroupNamespace>,
    ctx: &Context,
) -> Result<()> {
    check_set_ns_perms(target_ns, ctx)?;

    builder.cgroup_ns(target_ns.clone());

    Ok(())
}

fn set_ipc_ns(
    builder: &mut NsProxyBuilder,
    target_ns: &Arc<IpcNamespace>,
    ctx: &Context,
) -> Result<()> {
    check_set_ns_perms(target_ns, ctx)?;

    builder.ipc_ns(target_ns.clone());

    Ok(())
}

fn set_mnt_ns(
    builder: &mut NsProxyBuilder,
    target_ns: &Arc<MountNamespace>,
    ctx: &Context,
) -> Result<()> {
    check_set_ns_perms(target_ns, ctx)?;

    check_current_user_ns_cap(ctx, CapSet::SYS_CHROOT)?;

    if ctx.thread_local.is_fs_shared() {
        return Err(errno!(
            EINVAL,
            "setting a mount namespace is not allowed with shared filesystem information"
        ));
    }

    builder.mnt_ns(target_ns.clone());

    Ok(())
}

fn set_uts_ns(
    builder: &mut NsProxyBuilder,
    target_ns: &Arc<UtsNamespace>,
    ctx: &Context,
) -> Result<()> {
    check_set_ns_perms(target_ns, ctx)?;

    builder.uts_ns(target_ns.clone());

    Ok(())
}

fn set_pid_ns_for_children(target_ns: Arc<PidNamespace>, ctx: &Context) -> Result<()> {
    if target_ns.state() != PidNsState::Alive {
        return Err(errno!(
            EINVAL,
            "the target pid namespace is not alive"
        ));
    }

    // Verify the thread has `SYS_ADMIN` in the target namespace's owner
    // and in its current user namespace.
    check_set_ns_perms(&target_ns, ctx)?;

    let current_active = ctx.process.active_pid_ns();
    if !current_active.is_same_or_ancestor_of(&target_ns) {
        return Err(errno!(
            EINVAL,
            "the target pid namespace must be the current one or a descendant"
        ));
    }

    let mut pid_ns_for_children = ctx.posix_thread.pid_ns_for_children().lock();
    *pid_ns_for_children = if Arc::ptr_eq(current_active, &target_ns) {
        PidNsForChildren::SameAsActive
    } else {
        PidNsForChildren::Target(target_ns)
    };

    Ok(())
}

fn check_set_ns_perms<T: NsCommonOps>(target_ns: &Arc<T>, ctx: &Context) -> Result<()> {
    // Verify the thread has `SYS_ADMIN` capability in the target namespace's
    // owner and in its current user namespace.
    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        target_ns.owner_user_ns().unwrap().as_ref(),
        ctx.posix_thread,
        CapSet::SYS_ADMIN,
    ))?;
    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        ctx.thread_local.borrow_user_ns().as_ref(),
        ctx.posix_thread,
        CapSet::SYS_ADMIN,
    ))?;

    Ok(())
}

fn check_current_user_ns_cap(ctx: &Context, cap: CapSet) -> Result<()> {
    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        ctx.thread_local.borrow_user_ns().as_ref(),
        ctx.posix_thread,
        cap,
    ))
}
