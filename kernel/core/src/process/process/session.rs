// SPDX-License-Identifier: MPL-2.0

use super::{BOOTSTRAP_SID, Process, ProcessGroup, Sid, Terminal};
use crate::{
    prelude::*,
    process::{KernelPid, PidChain, PidNamespace},
};

/// A session.
///
/// A session is a collection of related process groups, which has a unique identifier SID (i.e.,
/// [`Sid`]) in every PID namespace where it is visible. Process groups and sessions form a
/// two-level hierarchical relationship between processes.
///
/// **Leader**: A *session leader* is the process that creates the session and whose process ID is
/// equal to the session ID.
///
/// **Controlling terminal**: A terminal can be used to manage all processes in the session. The
/// controlling terminal is established when the session leader first opens a terminal.
pub(crate) struct Session {
    owner_pid_ns: Arc<PidNamespace>,
    kernel_sid: KernelPid,
    sid_chain: PidChain,
    leader: Weak<Process>,
    inner: Mutex<Inner>,
}

struct Inner {
    process_groups: BTreeMap<KernelPid, Weak<ProcessGroup>>,
    terminal: Option<Arc<dyn Terminal>>,
}

impl Session {
    /// Creates a new session and a new process group with one process.
    ///
    /// The SID and the PGID chains are the same as the process ID chain, which means that the
    /// process will become the leader process of the new session and the new process group.
    ///
    /// The caller needs to ensure that the process does not belong to other process group or other
    /// session.
    pub(super) fn new_pair(process: Arc<Process>) -> (Arc<Self>, Arc<ProcessGroup>) {
        let session = Arc::new(Self {
            owner_pid_ns: process.active_pid_ns().clone(),
            kernel_sid: process.kernel_pid(),
            sid_chain: process.pid_chain().clone(),
            leader: Arc::downgrade(&process),
            inner: Mutex::new(Inner {
                process_groups: BTreeMap::new(),
                terminal: None,
            }),
        });

        let process_group = ProcessGroup::new(process, session.clone());
        session
            .inner
            .lock()
            .process_groups
            .insert(process_group.kernel_pgid(), Arc::downgrade(&process_group));

        (session, process_group)
    }

    /// Creates the bootstrap session/process-group pair for the init process.
    ///
    /// The caller needs to ensure that the process is the init process
    /// and does not belong to other process group or other session.
    pub(super) fn new_bootstrap_pair(process: &Arc<Process>) -> (Arc<Self>, Arc<ProcessGroup>) {
        debug_assert!(process.is_root_pid_ns_init());

        let session = Arc::new(Self {
            owner_pid_ns: process.active_pid_ns().clone(),
            kernel_sid: process.kernel_pid(),
            sid_chain: PidChain::one(process.active_pid_ns().clone(), BOOTSTRAP_SID),
            leader: Arc::downgrade(process),
            inner: Mutex::new(Inner {
                process_groups: BTreeMap::new(),
                terminal: None,
            }),
        });

        let process_group = ProcessGroup::new_bootstrap(process, session.clone());
        session.lock().insert_process_group(&process_group);

        (session, process_group)
    }

    /// Returns the PID namespace that owns this session.
    #[expect(dead_code)]
    pub(crate) fn owner_pid_ns(&self) -> &Arc<PidNamespace> {
        &self.owner_pid_ns
    }

    /// Returns the stable kernel-global identifier of the session.
    #[expect(dead_code)]
    pub(crate) fn kernel_sid(&self) -> KernelPid {
        self.kernel_sid
    }

    /// Returns the leader process of the session, if it is still alive.
    #[expect(dead_code)]
    pub(crate) fn leader(&self) -> Option<Arc<Process>> {
        self.leader.upgrade()
    }

    /// Returns the session identifier, as observed from the innermost namespace.
    pub(crate) fn sid(&self) -> Sid {
        self.canonical_sid_unchecked()
    }

    /// Returns the SID as observed from `ns`, if visible there.
    pub(crate) fn sid_in(&self, ns: &PidNamespace) -> Option<Sid> {
        self.sid_chain.nr_in(ns)
    }

    pub(crate) fn sid_chain(&self) -> &PidChain {
        &self.sid_chain
    }

    pub(super) fn canonical_sid_unchecked(&self) -> Sid {
        self.sid_chain.active_link().nr()
    }

    /// Returns whether the process is the session leader.
    pub(super) fn is_leader(&self, process: &Process) -> bool {
        self.kernel_sid == process.kernel_pid()
    }

    /// Acquires a lock on the session.
    pub(crate) fn lock(&self) -> SessionGuard<'_> {
        SessionGuard {
            inner: self.inner.lock(),
        }
    }
}

/// A scoped lock guard for a session.
///
/// It provides some public methods to prevent the exposure of the inner type.
#[clippy::has_significant_drop]
#[must_use]
pub(crate) struct SessionGuard<'a> {
    inner: MutexGuard<'a, Inner>,
}

impl SessionGuard<'_> {
    /// Sets the controlling terminal of the session.
    ///
    /// The caller needs to ensure that the job control of the old and new controlling terminals
    /// are properly updated and synchronized.
    pub(super) fn set_terminal(&mut self, terminal: Option<Arc<dyn Terminal>>) {
        self.inner.terminal = terminal;
    }

    /// Returns the controlling terminal of the session.
    pub(crate) fn terminal(&self) -> Option<&Arc<dyn Terminal>> {
        self.inner.terminal.as_ref()
    }

    /// Inserts a process group into the session.
    ///
    /// The caller needs to ensure that the process group didn't previously belong to the session,
    /// but now does.
    pub(in crate::process) fn insert_process_group(&mut self, process_group: &Arc<ProcessGroup>) {
        let old_process_group = self
            .inner
            .process_groups
            .insert(process_group.kernel_pgid(), Arc::downgrade(process_group));
        debug_assert!(old_process_group.is_none());
    }

    /// Removes a process group from the session.
    ///
    /// The caller needs to ensure that the process group previously belonged to the session, but
    /// now doesn't.
    pub(in crate::process) fn remove_process_group(&mut self, pgid: &KernelPid) {
        self.inner.process_groups.remove(pgid);
    }

    /// Returns whether the session is empty.
    pub(in crate::process) fn is_empty(&self) -> bool {
        self.inner.process_groups.is_empty()
    }
}
