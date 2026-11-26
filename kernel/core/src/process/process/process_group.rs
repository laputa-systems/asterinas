// SPDX-License-Identifier: MPL-2.0

use alloc::collections::btree_map::Values;

use super::{BOOTSTRAP_PGID, BOOTSTRAP_SID, Pgid, Process, Session};
use crate::{
    prelude::*,
    process::{KernelPid, PidChain, PidNamespace, signal::signals::Signal},
};

/// A process group.
///
/// A process group represents a set of processes. It is identified by a PGID
/// (i.e., [`Pgid`]) in every PID namespace where it is visible; the
/// [`PidChain`] records the per-namespace numbers. The group is owned by the
/// PID namespace that was active when its leader was created.
pub(crate) struct ProcessGroup {
    owner_pid_ns: Arc<PidNamespace>,
    kernel_pgid: KernelPid,
    pgid_chain: PidChain,
    leader: Weak<Process>,
    session: Arc<Session>,
    inner: Mutex<Inner>,
}

struct Inner {
    processes: BTreeMap<KernelPid, Weak<Process>>,
}

impl ProcessGroup {
    /// Creates a new process group with one process.
    ///
    /// The PGID chain is the same as the process's PID chain, which means that the process will
    /// become the leader process of the new process group.
    ///
    /// The caller needs to ensure that the process does not belong to other process group.
    pub(super) fn new(process: Arc<Process>, session: Arc<Session>) -> Arc<Self> {
        Self::new_with(
            process.pid_chain().clone(),
            process.kernel_pid(),
            &process,
            session,
        )
    }

    /// Creates the bootstrap process group for the init process.
    ///
    /// The caller needs to ensure that the process is the init process,
    /// the process does not belong to other process group, and
    /// the session is the bootstrap session.
    pub(super) fn new_bootstrap(process: &Arc<Process>, session: Arc<Session>) -> Arc<Self> {
        debug_assert!(process.is_root_pid_ns_init());
        debug_assert_eq!(session.sid(), BOOTSTRAP_SID);

        Self::new_with(
            PidChain::one(process.active_pid_ns().clone(), BOOTSTRAP_PGID),
            process.kernel_pid(),
            process,
            session,
        )
    }

    fn new_with(
        pgid_chain: PidChain,
        kernel_pgid: KernelPid,
        process: &Arc<Process>,
        session: Arc<Session>,
    ) -> Arc<Self> {
        let inner = {
            let mut processes = BTreeMap::new();
            processes.insert(process.kernel_pid(), Arc::downgrade(process));
            Inner { processes }
        };

        Arc::new(ProcessGroup {
            owner_pid_ns: process.active_pid_ns().clone(),
            kernel_pgid,
            pgid_chain,
            leader: Arc::downgrade(process),
            session,
            inner: Mutex::new(inner),
        })
    }

    /// Returns the PID namespace that owns this process group.
    pub(crate) fn owner_pid_ns(&self) -> &Arc<PidNamespace> {
        &self.owner_pid_ns
    }

    /// Returns the stable kernel-global identifier of the process group.
    pub(crate) fn kernel_pgid(&self) -> KernelPid {
        self.kernel_pgid
    }

    /// Returns the leader process of the group, if it is still alive.
    #[expect(dead_code)]
    pub(crate) fn leader(&self) -> Option<Arc<Process>> {
        self.leader.upgrade()
    }

    /// Returns the session to which the process group belongs.
    pub(crate) fn session(&self) -> &Arc<Session> {
        &self.session
    }

    /// Returns the process group identifier, as observed from the innermost namespace.
    pub(crate) fn pgid(&self) -> Pgid {
        self.canonical_pgid_unchecked()
    }

    /// Returns the PGID as observed from `ns`, if visible there.
    pub(crate) fn pgid_in(&self, ns: &PidNamespace) -> Option<Pgid> {
        self.pgid_chain.nr_in(ns)
    }

    pub(crate) fn pgid_chain(&self) -> &PidChain {
        &self.pgid_chain
    }

    pub(super) fn canonical_pgid_unchecked(&self) -> Pgid {
        self.pgid_chain.active_link().nr()
    }

    /// Acquires a lock on the process group.
    pub(crate) fn lock(&self) -> ProcessGroupGuard<'_> {
        ProcessGroupGuard {
            inner: self.inner.lock(),
        }
    }

    /// Broadcasts the signal to all processes in the process group.
    ///
    /// This method should only be used to broadcast fault signals and kernel signals.
    //
    // TODO: Do some checks to forbid user signals.
    pub(crate) fn broadcast_signal(&self, signal: impl Signal + Clone + 'static) {
        for process in self
            .inner
            .lock()
            .processes
            .values()
            .filter_map(Weak::upgrade)
        {
            process.enqueue_signal(Box::new(signal.clone()));
        }
    }
}

/// A scoped lock guard for a process group.
///
/// It provides some public methods to prevent the exposure of the inner type.
#[clippy::has_significant_drop]
#[must_use]
pub(crate) struct ProcessGroupGuard<'a> {
    inner: MutexGuard<'a, Inner>,
}

impl ProcessGroupGuard<'_> {
    /// Returns an iterator over the processes in the process group.
    pub(crate) fn iter(&self) -> ProcessGroupIter<'_> {
        ProcessGroupIter {
            inner: self.inner.processes.values(),
        }
    }

    /// Inserts a process into the process group.
    ///
    /// The caller needs to ensure that the process didn't previously belong to the process group,
    /// but now does.
    pub(in crate::process) fn insert_process(&mut self, process: &Arc<Process>) {
        let old_process = self
            .inner
            .processes
            .insert(process.kernel_pid(), Arc::downgrade(process));
        debug_assert!(old_process.is_none());
    }

    /// Removes a process from the process group.
    ///
    /// The caller needs to ensure that the process previously belonged to the process group, but
    /// now doesn't.
    pub(in crate::process) fn remove_process(&mut self, pid: &KernelPid) {
        let process = self.inner.processes.remove(pid);
        debug_assert!(process.is_some());
    }

    /// Returns whether the process group is empty.
    pub(in crate::process) fn is_empty(&self) -> bool {
        self.inner.processes.is_empty()
    }
}

/// An iterator over the processes of the process group.
pub(crate) struct ProcessGroupIter<'a> {
    inner: Values<'a, KernelPid, Weak<Process>>,
}

impl<'a> Iterator for ProcessGroupIter<'a> {
    type Item = Arc<Process>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.by_ref().find_map(Weak::upgrade)
    }
}
