// SPDX-License-Identifier: MPL-2.0

//! PID namespaces.
//!
//! A PID namespace isolates the process ID number space: processes inside a
//! PID namespace see themselves and their descendants with namespace-local
//! PIDs, while processes in ancestor namespaces observe the same processes
//! under different, ancestor-local PIDs.
//!
//! This design is ported from upstream Asterinas PR #3025 ("Support PID
//! namespace"), adapted to the fork's process and namespace framework
//! (`kernel/core/src/...` layout, [`NsProxy`] singletons, the bootstrap
//! process group/session, and the fork's [`PosixThreadBuilder`] API).

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use spin::Once;

use crate::{
    fs::pseudofs::{NsCommonOps, NsType, StashedDentry},
    prelude::*,
    process::{
        Pgid, Pid, Process, ProcessGroup, Session, Sid, UserNamespace,
        posix_thread::AsPosixThread,
    },
    thread::{Thread, Tid},
};

/// The maximum allowed nesting depth of PID namespaces.
pub(crate) const PID_NS_LEVEL_LIMIT: u32 = 32;

/// A stable, kernel-global identifier for a thread or a process.
///
/// Unlike namespace-local PIDs ([`Pid`]/[`Tid`]), which are only meaningful
/// inside a single PID namespace, a [`KernelId`] uniquely identifies a kernel
/// object across all namespaces. It is used as the key for internal maps
/// (e.g., parent/children relations, process groups) that must be stable
/// regardless of the observer's namespace.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct KernelId(u64);

impl KernelId {
    #[expect(dead_code)]
    pub(crate) const fn as_u64(self) -> u64 {
        self.0
    }
}

pub(crate) type KernelPid = KernelId;
pub(crate) type KernelTid = KernelId;

pub(crate) struct KernelIdAllocator(AtomicU64);

impl KernelIdAllocator {
    const fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    pub(crate) fn alloc(&self) -> Result<KernelId> {
        let id = self
            .0
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| errno!(EAGAIN, "kernel ids are exhausted"))?;
        Ok(KernelId(id))
    }

    pub(crate) fn last_allocated(&self) -> u64 {
        self.0.load(Ordering::SeqCst).saturating_sub(1)
    }
}

pub(crate) fn kernel_id_allocator() -> &'static KernelIdAllocator {
    static ALLOCATOR: KernelIdAllocator = KernelIdAllocator::new();
    &ALLOCATOR
}

/// A global lock that serializes mutations of the PID namespace graph.
///
/// This must be held when inserting or removing threads, processes, process
/// groups, or sessions across namespaces, and when creating processes whose
/// namespace placement is being decided (clone/fork), so that concurrent
/// clones, exits, and reaps observe a consistent graph.
pub(crate) fn pid_ns_graph_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

/// The lifecycle state of a PID namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PidNsState {
    /// The namespace was created but its init process has not been installed yet.
    PendingInit = 0,
    /// The namespace has a live init process and accepts new children.
    Alive = 1,
    /// The namespace init process has exited; no new children are accepted.
    Dying = 2,
}

pub(crate) struct AtomicPidNsState(AtomicU8);

impl AtomicPidNsState {
    pub(crate) const fn new(state: PidNsState) -> Self {
        Self(AtomicU8::new(state as u8))
    }

    pub(crate) fn load(&self) -> PidNsState {
        match self.0.load(Ordering::Acquire) {
            0 => PidNsState::PendingInit,
            1 => PidNsState::Alive,
            2 => PidNsState::Dying,
            _ => unreachable!(),
        }
    }

    pub(crate) fn store(&self, state: PidNsState) {
        self.0.store(state as u8, Ordering::Release);
    }
}

/// A PID namespace.
///
/// Each namespace (except the initial one) has a parent namespace and owns an
/// allocator for the IDs that are visible inside it. Every thread, process,
/// process group, and session that is visible in this namespace is recorded
/// in [`NsVisiblePidTable`] under its namespace-local number.
pub(crate) struct PidNamespace {
    parent: Option<Arc<PidNamespace>>,
    level: u32,
    owner_user_ns: Arc<UserNamespace>,
    state: AtomicPidNsState,
    pending_init_lock: Mutex<()>,
    allocator: AtomicU32,
    visible_table: Mutex<NsVisiblePidTable>,
    child_reaper: Mutex<Weak<Process>>,
    stashed_dentry: StashedDentry,
}

pub(crate) struct NsVisiblePidTable {
    entries: BTreeMap<u32, Arc<PidEntry>>,
}

pub(crate) struct PidEntry {
    inner: Mutex<PidEntryInner>,
}

struct PidEntryInner {
    thread: Weak<Thread>,
    process: Weak<Process>,
    process_group: Weak<ProcessGroup>,
    session: Weak<Session>,
}

/// A single (namespace, number) pair identifying a kernel object in one PID
/// namespace.
#[derive(Clone)]
pub(crate) struct PidLink {
    ns: Arc<PidNamespace>,
    nr: u32,
}

/// The chain of (namespace, number) pairs identifying a thread, process,
/// process group, or session in every ancestor namespace up to the initial
/// PID namespace.
#[derive(Clone)]
pub(crate) struct PidChain {
    numbers: Box<[PidLink]>,
}

/// Selects the PID namespace that future children of a thread will enter.
///
/// This is per-thread state (mirroring Linux's `nsproxy->pid_ns_for_children`
/// semantics): `unshare(CLONE_NEWPID)` and `setns()` with a PID namespace
/// file only affect the calling thread's future children.
#[derive(Clone)]
pub(crate) enum PidNsForChildren {
    SameAsActive,
    Target(Arc<PidNamespace>),
}

impl PidEntry {
    fn new() -> Self {
        Self {
            inner: Mutex::new(PidEntryInner {
                thread: Weak::new(),
                process: Weak::new(),
                process_group: Weak::new(),
                session: Weak::new(),
            }),
        }
    }

    fn thread(&self) -> Option<Arc<Thread>> {
        self.inner.lock().thread.upgrade()
    }

    fn process(&self) -> Option<Arc<Process>> {
        self.inner.lock().process.upgrade()
    }

    fn process_group(&self) -> Option<Arc<ProcessGroup>> {
        self.inner.lock().process_group.upgrade()
    }

    fn set_thread(&self, thread: &Arc<Thread>) {
        self.inner.lock().thread = Arc::downgrade(thread);
    }

    fn clear_thread(&self) {
        self.inner.lock().thread = Weak::new();
    }

    fn set_process(&self, process: &Arc<Process>) {
        self.inner.lock().process = Arc::downgrade(process);
    }

    fn clear_process(&self) {
        self.inner.lock().process = Weak::new();
    }

    fn set_process_group(&self, process_group: &Arc<ProcessGroup>) {
        self.inner.lock().process_group = Arc::downgrade(process_group);
    }

    fn clear_process_group(&self) {
        self.inner.lock().process_group = Weak::new();
    }

    fn set_session(&self, session: &Arc<Session>) {
        self.inner.lock().session = Arc::downgrade(session);
    }

    fn clear_session(&self) {
        self.inner.lock().session = Weak::new();
    }

    fn is_empty(&self) -> bool {
        let inner = self.inner.lock();
        inner.thread.strong_count() == 0
            && inner.process.strong_count() == 0
            && inner.process_group.strong_count() == 0
            && inner.session.strong_count() == 0
    }
}

impl NsVisiblePidTable {
    const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    fn get_or_create_entry(&mut self, nr: u32) -> Arc<PidEntry> {
        self.entries
            .entry(nr)
            .or_insert_with(|| Arc::new(PidEntry::new()))
            .clone()
    }

    fn try_remove_entry(&mut self, nr: u32) {
        if let Some(entry) = self.entries.get(&nr)
            && entry.is_empty()
        {
            self.entries.remove(&nr);
        }
    }

    fn insert_thread(&mut self, nr: Tid, thread: &Arc<Thread>) {
        self.get_or_create_entry(nr).set_thread(thread);
    }

    fn remove_thread(&mut self, nr: Tid) {
        if let Some(entry) = self.entries.get(&nr) {
            entry.clear_thread();
        }
        self.try_remove_entry(nr);
    }

    fn insert_process(&mut self, nr: Pid, process: &Arc<Process>) {
        self.get_or_create_entry(nr).set_process(process);
    }

    fn remove_process(&mut self, nr: Pid) {
        if let Some(entry) = self.entries.get(&nr) {
            entry.clear_process();
        }
        self.try_remove_entry(nr);
    }

    fn insert_process_group(&mut self, nr: Pgid, process_group: &Arc<ProcessGroup>) {
        self.get_or_create_entry(nr)
            .set_process_group(process_group);
    }

    fn remove_process_group(&mut self, nr: Pgid) {
        if let Some(entry) = self.entries.get(&nr) {
            entry.clear_process_group();
        }
        self.try_remove_entry(nr);
    }

    fn insert_session(&mut self, nr: Sid, session: &Arc<Session>) {
        self.get_or_create_entry(nr).set_session(session);
    }

    fn remove_session(&mut self, nr: Sid) {
        if let Some(entry) = self.entries.get(&nr) {
            entry.clear_session();
        }
        self.try_remove_entry(nr);
    }
}

impl PidNamespace {
    /// Returns the initial PID namespace shared by all processes at boot.
    pub(crate) fn get_init_singleton() -> &'static Arc<Self> {
        static INIT: Once<Arc<PidNamespace>> = Once::new();
        INIT.call_once(|| {
            Arc::new(Self {
                parent: None,
                level: 0,
                owner_user_ns: UserNamespace::get_init_singleton().clone(),
                state: AtomicPidNsState::new(PidNsState::Alive),
                pending_init_lock: Mutex::new(()),
                // IDs 0 and 1 are reserved: the init process takes 1, and the
                // fork's bootstrap process group/session take 0.
                allocator: AtomicU32::new(2),
                visible_table: Mutex::new(NsVisiblePidTable::new()),
                child_reaper: Mutex::new(Weak::new()),
                stashed_dentry: StashedDentry::new(),
            })
        })
    }

    /// Creates a new child PID namespace owned by `owner_user_ns`.
    ///
    /// The new namespace starts in the [`PidNsState::PendingInit`] state; its
    /// first child becomes the namespace init and flips it to
    /// [`PidNsState::Alive`].
    pub(crate) fn new_child(
        parent: Arc<PidNamespace>,
        owner_user_ns: Arc<UserNamespace>,
    ) -> Result<Arc<Self>> {
        let next_depth = parent.level + 2;
        if next_depth > PID_NS_LEVEL_LIMIT {
            return Err(errno!(
                EINVAL,
                "the pid namespace nesting limit is exceeded"
            ));
        }

        Ok(Arc::new(Self {
            parent: Some(parent.clone()),
            level: parent.level + 1,
            owner_user_ns,
            state: AtomicPidNsState::new(PidNsState::PendingInit),
            pending_init_lock: Mutex::new(()),
            allocator: AtomicU32::new(1),
            visible_table: Mutex::new(NsVisiblePidTable::new()),
            child_reaper: Mutex::new(Weak::new()),
            stashed_dentry: StashedDentry::new(),
        }))
    }

    pub(crate) fn parent_ns(&self) -> Option<&Arc<PidNamespace>> {
        self.parent.as_ref()
    }

    #[expect(dead_code)]
    pub(crate) fn level(&self) -> u32 {
        self.level
    }

    pub(crate) fn state(&self) -> PidNsState {
        self.state.load()
    }

    pub(crate) fn set_state(&self, state: PidNsState) {
        self.state.store(state);
    }

    pub(crate) fn pending_init_lock(&self) -> &Mutex<()> {
        &self.pending_init_lock
    }

    /// Returns the init (child reaper) process of this namespace, if any.
    pub(crate) fn child_reaper(&self) -> Option<Arc<Process>> {
        self.child_reaper.lock().upgrade()
    }

    pub(crate) fn set_child_reaper(&self, process: &Arc<Process>) {
        *self.child_reaper.lock() = Arc::downgrade(process);
    }

    /// Returns whether `self` is the same as, or an ancestor of, `other`.
    pub(crate) fn is_same_or_ancestor_of(self: &Arc<Self>, other: &Arc<Self>) -> bool {
        let mut current = Some(other.clone());
        while let Some(ns) = current {
            if Arc::ptr_eq(self, &ns) {
                return true;
            }
            current = ns.parent.clone();
        }
        false
    }

    #[expect(dead_code)]
    pub(crate) fn is_same_or_descendant_of(self: &Arc<Self>, other: &Arc<Self>) -> bool {
        other.is_same_or_ancestor_of(self)
    }

    /// Returns the chain of namespaces from the initial namespace down to
    /// `self`.
    pub(crate) fn ancestor_chain(self: &Arc<Self>) -> Box<[Arc<PidNamespace>]> {
        let mut chain = Vec::new();
        let mut current = Some(self.clone());
        while let Some(ns) = current {
            chain.push(ns.clone());
            current = ns.parent.clone();
        }
        chain.reverse();
        chain.into_boxed_slice()
    }

    /// Allocates a fresh ID that is visible inside this namespace.
    pub(crate) fn alloc_visible_id(&self) -> Result<u32> {
        let next = self
            .allocator
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| errno!(EAGAIN, "pid space is exhausted"))?;
        Ok(next)
    }

    /// Allocates one visible ID in this namespace and in every ancestor,
    /// returning the full [`PidChain`].
    pub(crate) fn alloc_chain(self: &Arc<Self>) -> Result<PidChain> {
        let chain = self.ancestor_chain();
        let mut numbers = Vec::with_capacity(chain.len());
        for ns in chain {
            let nr = ns.alloc_visible_id()?;
            numbers.push(PidLink { ns, nr });
        }
        Ok(PidChain::from_links(numbers))
    }

    pub(crate) fn lookup_thread(&self, tid: Tid) -> Option<Arc<Thread>> {
        self.visible_table
            .lock()
            .entries
            .get(&tid)
            .and_then(|entry| entry.thread())
    }

    pub(crate) fn lookup_process(&self, pid: Pid) -> Option<Arc<Process>> {
        self.visible_table
            .lock()
            .entries
            .get(&pid)
            .and_then(|entry| entry.process())
    }

    pub(crate) fn lookup_process_group(&self, pgid: Pgid) -> Option<Arc<ProcessGroup>> {
        self.visible_table
            .lock()
            .entries
            .get(&pgid)
            .and_then(|entry| entry.process_group())
    }

    pub(crate) fn contains_process_group(&self, pgid: Pgid) -> bool {
        self.lookup_process_group(pgid).is_some()
    }

    /// Returns all processes visible in this namespace.
    pub(crate) fn visible_processes(&self) -> Vec<Arc<Process>> {
        self.visible_table
            .lock()
            .entries
            .values()
            .filter_map(|entry| entry.process())
            .collect()
    }

    /// Returns all threads visible in this namespace.
    pub(crate) fn visible_threads(&self) -> Vec<Arc<Thread>> {
        self.visible_table
            .lock()
            .entries
            .values()
            .filter_map(|entry| entry.thread())
            .collect()
    }

    pub(crate) fn visible_process_count(&self) -> usize {
        self.visible_processes().len()
    }

    /// Inserts a process into every namespace in its PID chain.
    ///
    /// The caller must hold [`pid_ns_graph_lock`].
    pub(in crate::process) fn insert_process_across_namespaces_with_pid_ns_graph_lock(
        process: Arc<Process>,
    ) {
        for link in process.pid_chain().links() {
            link.ns().insert_process_chain(&process);
        }
    }

    /// Removes a process from every namespace in its PID chain.
    ///
    /// The caller must hold [`pid_ns_graph_lock`].
    pub(in crate::process) fn remove_process_across_namespaces_with_pid_ns_graph_lock(
        process: &Process,
    ) {
        for link in process.pid_chain().links() {
            link.ns().remove_process_chain(process);
        }
    }

    /// Inserts a thread into every namespace in its TID chain.
    ///
    /// The caller must hold [`pid_ns_graph_lock`].
    pub(in crate::process) fn insert_thread_across_namespaces_with_pid_ns_graph_lock(
        thread: Arc<Thread>,
    ) {
        let posix_thread = thread.as_posix_thread().unwrap();
        let tid_chain = posix_thread.tid_chain().clone();
        for link in tid_chain.links() {
            link.ns().insert_thread_chain(&thread, &tid_chain);
        }
    }

    /// Removes a thread from every namespace in `tid_chain`.
    ///
    /// The caller must hold [`pid_ns_graph_lock`].
    pub(in crate::process) fn remove_thread_across_namespaces_with_pid_ns_graph_lock(
        tid_chain: &PidChain,
    ) {
        for link in tid_chain.links() {
            link.ns().remove_thread_chain(tid_chain);
        }
    }

    /// Inserts a process group into every namespace in its PGID chain.
    ///
    /// The caller must hold [`pid_ns_graph_lock`].
    pub(in crate::process) fn insert_process_group_across_namespaces_with_pid_ns_graph_lock(
        process_group: Arc<ProcessGroup>,
    ) {
        for link in process_group.pgid_chain().links() {
            link.ns()
                .insert_process_group_chain(&process_group, process_group.pgid_chain());
        }
    }

    /// Removes a process group from every namespace in its PGID chain.
    ///
    /// The caller must hold [`pid_ns_graph_lock`].
    pub(in crate::process) fn remove_process_group_across_namespaces_with_pid_ns_graph_lock(
        process_group: &ProcessGroup,
    ) {
        for link in process_group.pgid_chain().links() {
            link.ns()
                .remove_process_group_chain(process_group.pgid_chain());
        }
    }

    /// Inserts a session into every namespace in its SID chain.
    ///
    /// The caller must hold [`pid_ns_graph_lock`].
    pub(in crate::process) fn insert_session_across_namespaces_with_pid_ns_graph_lock(
        session: Arc<Session>,
    ) {
        for link in session.sid_chain().links() {
            link.ns()
                .insert_session_chain(&session, session.sid_chain());
        }
    }

    /// Removes a session from every namespace in its SID chain.
    ///
    /// The caller must hold [`pid_ns_graph_lock`].
    pub(in crate::process) fn remove_session_across_namespaces_with_pid_ns_graph_lock(
        session: &Session,
    ) {
        for link in session.sid_chain().links() {
            link.ns().remove_session_chain(session.sid_chain());
        }
    }

    pub(crate) fn insert_process_chain(&self, process: &Arc<Process>) {
        let mut table = self.visible_table.lock();
        for link in process.pid_chain().links() {
            if core::ptr::eq(Arc::as_ptr(&link.ns), self) {
                table.insert_process(link.nr, process);
            }
        }
    }

    pub(crate) fn insert_thread_chain(&self, thread: &Arc<Thread>, tid_chain: &PidChain) {
        let mut table = self.visible_table.lock();
        for link in tid_chain.links() {
            if core::ptr::eq(Arc::as_ptr(&link.ns), self) {
                table.insert_thread(link.nr, thread);
            }
        }
    }

    pub(crate) fn remove_process_chain(&self, process: &Process) {
        let mut table = self.visible_table.lock();
        for link in process.pid_chain().links() {
            if core::ptr::eq(Arc::as_ptr(&link.ns), self) {
                table.remove_process(link.nr);
            }
        }
    }

    pub(crate) fn remove_thread_chain(&self, tid_chain: &PidChain) {
        let mut table = self.visible_table.lock();
        for link in tid_chain.links() {
            if core::ptr::eq(Arc::as_ptr(&link.ns), self) {
                table.remove_thread(link.nr);
            }
        }
    }

    pub(crate) fn insert_process_group_chain(
        &self,
        process_group: &Arc<ProcessGroup>,
        pgid_chain: &PidChain,
    ) {
        let mut table = self.visible_table.lock();
        for link in pgid_chain.links() {
            if core::ptr::eq(Arc::as_ptr(&link.ns), self) {
                table.insert_process_group(link.nr, process_group);
            }
        }
    }

    pub(crate) fn remove_process_group_chain(&self, pgid_chain: &PidChain) {
        let mut table = self.visible_table.lock();
        for link in pgid_chain.links() {
            if core::ptr::eq(Arc::as_ptr(&link.ns), self) {
                table.remove_process_group(link.nr);
            }
        }
    }

    pub(crate) fn insert_session_chain(&self, session: &Arc<Session>, sid_chain: &PidChain) {
        let mut table = self.visible_table.lock();
        for link in sid_chain.links() {
            if core::ptr::eq(Arc::as_ptr(&link.ns), self) {
                table.insert_session(link.nr, session);
            }
        }
    }

    pub(crate) fn remove_session_chain(&self, sid_chain: &PidChain) {
        let mut table = self.visible_table.lock();
        for link in sid_chain.links() {
            if core::ptr::eq(Arc::as_ptr(&link.ns), self) {
                table.remove_session(link.nr);
            }
        }
    }
}

impl PidChain {
    pub(crate) fn from_links(numbers: Vec<PidLink>) -> Self {
        Self {
            numbers: numbers.into_boxed_slice(),
        }
    }

    pub(crate) fn one(ns: Arc<PidNamespace>, nr: u32) -> Self {
        Self::from_links(vec![PidLink { ns, nr }])
    }

    pub(crate) fn links(&self) -> &[PidLink] {
        &self.numbers
    }

    /// Returns the number identifying the object in `ns`, if visible there.
    pub(crate) fn nr_in(&self, ns: &PidNamespace) -> Option<u32> {
        self.numbers
            .iter()
            .find(|link| core::ptr::eq(Arc::as_ptr(&link.ns), ns))
            .map(|link| link.nr)
    }

    #[expect(dead_code)]
    pub(crate) fn contains_ns(&self, ns: &PidNamespace) -> bool {
        self.nr_in(ns).is_some()
    }

    /// Returns the link in the innermost (active) namespace.
    pub(crate) fn active_link(&self) -> &PidLink {
        self.numbers.last().unwrap()
    }
}

impl PidLink {
    pub(crate) fn ns(&self) -> &Arc<PidNamespace> {
        &self.ns
    }

    pub(crate) fn nr(&self) -> u32 {
        self.nr
    }
}

impl PidNsForChildren {
    /// Resolves the PID namespace that future children should enter.
    pub(crate) fn target(&self, active: &Arc<PidNamespace>) -> Arc<PidNamespace> {
        match self {
            Self::SameAsActive => active.clone(),
            Self::Target(ns) => ns.clone(),
        }
    }
}

impl NsCommonOps for PidNamespace {
    const TYPE: NsType = NsType::Pid;

    fn owner_user_ns(&self) -> Option<&Arc<UserNamespace>> {
        Some(&self.owner_user_ns)
    }

    fn parent(&self) -> Result<&Arc<Self>> {
        self.parent
            .as_ref()
            .ok_or_else(|| errno!(EPERM, "the initial pid namespace has no parent"))
    }

    fn stashed_dentry(&self) -> &StashedDentry {
        &self.stashed_dentry
    }
}
