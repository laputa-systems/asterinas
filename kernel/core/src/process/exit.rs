// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use super::{KernelPid, Pid, Process, Uid, posix_thread::AsPosixThread};
use crate::{
    events::IoEvents, fs::cgroupfs::CgroupMembership, prelude::*,
    process::{
        PidNamespace,
        namespace::pid_ns::pid_ns_graph_lock,
        signal::{
            c_types::siginfo_t,
            constants::{CLD_EXITED, CLD_KILLED, SIGCHLD, SIGKILL},
            signals::{kernel::KernelSignal, raw::RawSignal},
        },
    },
    thread::AsThread,
};

/// Exits the current POSIX process.
///
/// This is for internal use. Do NOT call this directly. When the last thread in the process exits,
/// [`do_exit`] or [`do_exit_group`] will invoke this method automatically.
///
/// [`do_exit`]: crate::process::posix_thread::do_exit
/// [`do_exit_group`]: crate::process::posix_thread::do_exit_group
pub(super) fn exit_process(
    current_process: &Process,
    uid: Uid,
    tracer: Option<Arc<crate::thread::Thread>>,
) {
    current_process.status().set_vfork_child(false);

    // Drop fields in `Process`.
    drop_after!(current_process.lock_vmar().set_vmar(None));

    // Move the children to the reaper process and send them signals. The children should see a new
    // parent when they receive the signal.
    let children = move_children_to_reaper_process(current_process);
    send_parent_death_signal(&children);
    drop(children);

    // Mark the current process as a zombie. After this point, it may be reaped concurrently and
    // removed from the process tree. For example, the process may no longer have a live parent if
    // the parent exits after reaping the process.
    //
    // This must happen after `move_children_to_reaper_process`. See the comments in
    // `find_reaper_process` for details.
    current_process.status().set_zombie();

    if let Some(tracer) = tracer {
        tracer
            .as_posix_thread()
            .unwrap()
            .process()
            .children_wait_queue()
            .wake_all();
    }

    current_process.pidfile_pollee.notify(IoEvents::IN);

    send_child_death_signal(current_process, uid);

    // Remove the process from the cgroup.
    let mut cgroup_guard = CgroupMembership::write_lock();
    cgroup_guard.move_process_to_root(current_process);
    drop(cgroup_guard);
}

/// Drops a value after releasing the lock or borrow guard.
///
/// For example, [`ThreadLocal::vmar`] needs to be borrowed during a context switch. This means that
/// the kernel may panic if we borrow it as mutable and tries to acquire a mutex while dropping the
/// last [`VmarHandle`]. This utility macro ensures that the value is dropped only after the borrow
/// guard has been released, preventing all these issues.
///
/// [`ThreadLocal::vmar`]: super::posix_thread::ThreadLocal::vmar
/// [`VmarHandle`]: crate::vm::vmar::VmarHandle
macro_rules! drop_after {
    ($expr:expr) => {
        let val = $expr;
        drop(val);
    };
}

pub(super) use drop_after;

/// Moves the children to a reaper process.
///
/// Returns the moved children. Note that no new processes can become this process's children after
/// this point, so the returned children reliably represent the set of children at the time the
/// process exits.
fn move_children_to_reaper_process(
    current_process: &Process,
) -> BTreeMap<KernelPid, Arc<Process>> {
    if current_process.is_root_pid_ns_init() {
        return BTreeMap::new();
    }

    if current_process.is_pid_namespace_init() {
        let _pid_ns_graph_guard = pid_ns_graph_lock().lock();
        current_process
            .active_pid_ns()
            .set_state(crate::process::PidNsState::Dying);
        drop(_pid_ns_graph_guard);
        kill_visible_processes_in_pid_namespace(current_process);
    }

    {
        let mut current_children = current_process.children().lock();
        if current_children.as_ref().is_some_and(BTreeMap::is_empty) {
            *current_children = None;
            return BTreeMap::new();
        }
    }

    let _pid_ns_graph_guard = pid_ns_graph_lock().lock();
    while let Some(reaper_process) = find_reaper_process(current_process) {
        if let Ok(children) = move_process_children(current_process, &reaper_process) {
            reaper_process.children_wait_queue().wake_all();
            return children;
        }
    }

    const INIT_PROCESS_PID: Pid = 1;

    let init_process = PidNamespace::get_init_singleton()
        .lookup_process(INIT_PROCESS_PID)
        .unwrap();
    let children = move_process_children(current_process, &init_process).unwrap();
    init_process.children_wait_queue().wake_all();

    children
}

/// Finds a reaper process for `current_process`.
///
/// If there is no reaper process for `current_process`, returns `None`.
/// Finds the nearest live reaper in an ancestor namespace of `pid_ns`.
fn first_live_ancestor_namespace_reaper(pid_ns: &Arc<PidNamespace>) -> Option<Arc<Process>> {
    let mut current_ns = pid_ns.parent_ns().cloned();
    while let Some(ns) = current_ns {
        if let Some(reaper) = ns.child_reaper()
            && !reaper.status().is_zombie()
        {
            return Some(reaper);
        }
        current_ns = ns.parent_ns().cloned();
    }
    None
}

fn find_reaper_process(current_process: &Process) -> Option<Arc<Process>> {
    let parent_ns = current_process.active_pid_ns();
    if matches!(
        parent_ns.state(),
        crate::process::PidNsState::Dying
    ) {
        return first_live_ancestor_namespace_reaper(parent_ns);
    }

    if !current_process.has_child_subreaper.load(Ordering::Acquire) {
        return parent_ns
            .child_reaper()
            .filter(|reaper| !reaper.status().is_zombie());
    }

    // The current process is not yet zombie (see `exit_process`), so it cannot have been reaped,
    // and it is still present in its parent's children map. An exiting parent will move the
    // current process to a new reaper (updating this `Weak` reference) before becoming zombie
    // itself. Therefore, the parent is always alive and `upgrade` cannot fail.
    let mut parent = current_process.parent().lock().process().upgrade().unwrap();

    loop {
        if !Arc::ptr_eq(parent.active_pid_ns(), parent_ns) {
            break;
        }

        if parent.is_child_subreaper() && !parent.status().is_zombie() {
            return Some(parent);
        }

        let grandparent = parent.parent().lock().process().upgrade();
        if let Some(grandparent) = grandparent {
            parent = grandparent;
        } else {
            // The grandparent was concurrently reaped and dropped, so we lost the path up the
            // ancestor chain. Retry from the current process's parent to pick up the latest reaper
            // assignment. This `upgrade` won't fail for the same reason explained above.
            parent = current_process.parent().lock().process().upgrade().unwrap();
        }
    }

    parent_ns
        .child_reaper()
        .filter(|reaper| !reaper.status().is_zombie())
}

/// Sends `SIGKILL` to all live processes visible in the exiting namespace init's namespace.
fn kill_visible_processes_in_pid_namespace(current_process: &Process) {
    for process in current_process.active_pid_ns().visible_processes() {
        if process.kernel_pid() == current_process.kernel_pid()
            || process.status().is_zombie()
        {
            continue;
        }
        process.enqueue_signal(Box::new(KernelSignal::new(SIGKILL)));
    }
}

/// Moves the children of `current_process` to be the children of `reaper_process`.
///
/// Returns the moved children on success. Otherwise, if the `reaper_process` is zombie, returns
/// `Err(())`.
fn move_process_children(
    current_process: &Process,
    reaper_process: &Arc<Process>,
) -> Result<BTreeMap<KernelPid, Arc<Process>>, ()> {
    // Lock order: children of process -> parent of process
    let mut reaper_process_children = reaper_process.children().lock();
    let Some(reaper_process_children) = reaper_process_children.as_mut() else {
        // The reaper process has exited, and it is not the init process
        // (since we never clear the init process's children).
        return Err(());
    };

    // We hold the lock of children while updating the children's parents.
    // This ensures when dealing with CLONE_PARENT,
    // the retrial will see an up-to-date real parent.
    let reaper_thread = {
        let tasks = reaper_process.tasks().lock();
        let Some(task) = tasks.as_slice().iter().find(|task| !task.as_thread().unwrap().is_exited()) else {
            return Err(());
        };
        Arc::downgrade(task.as_thread().unwrap())
    };
    let mut current_children = current_process.children().lock();
    let children = current_children.take().unwrap();

    let mut moved = BTreeMap::new();
    for (kernel_pid, mut relation) in children {
        let child_process = &relation.process;
        let visible_parent_pid = reaper_process
            .pid_in(child_process.active_pid_ns())
            .unwrap_or(0);
        child_process
            .parent
            .lock()
            .set_process_with_visible_pid(reaper_process, visible_parent_pid);
        moved.insert(kernel_pid, child_process.clone());
        relation.parent_thread = reaper_thread.clone();
        reaper_process_children.insert(kernel_pid, relation);
    }

    Ok(moved)
}

/// Sends parent-death signals to the children.
//
// FIXME: According to the Linux implementation, the signal should be sent when the POSIX thread
// that created the child exits, not when the whole process exits. For more details, see the
// "CAVEATS" section in <https://man7.org/linux/man-pages/man2/pr_set_pdeathsig.2const.html>.
fn send_parent_death_signal(children: &BTreeMap<KernelPid, Arc<Process>>) {
    for child in children.values() {
        let Some(signum) = child.parent_death_signal() else {
            continue;
        };

        // FIXME: Set `si_pid` in the `siginfo_t` argument.
        let signal = Box::new(KernelSignal::new(signum));
        child.enqueue_signal(signal);
    }
}

/// Sends a child-death signal to the parent.
fn send_child_death_signal(current_process: &Process, uid: Uid) {
    let Some(parent) = current_process.parent().lock().process().upgrade() else {
        return;
    };

    if let Some(signum) = current_process.exit_signal() {
        if signum == SIGCHLD {
            let exit_code = current_process.status().exit_code();
            let (code, status) = if exit_code & 0x7f == 0 {
                (CLD_EXITED, (exit_code >> 8) as i32)
            } else {
                (CLD_KILLED, (exit_code & 0x7f) as i32)
            };
            let mut info = siginfo_t::new(signum, code);
            // Report the child's PID as observed from the parent's PID namespace.
            let visible_pid = current_process
                .pid_in(parent.active_pid_ns())
                .unwrap_or(0);
            info.set_pid_uid(visible_pid, uid);
            info.set_status(status);
            parent.enqueue_signal(Box::new(RawSignal::new(info)));
        } else {
            parent.enqueue_signal(Box::new(KernelSignal::new(signum)));
        }
    }
    parent.children_wait_queue().wake_all();
}
