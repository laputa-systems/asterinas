// SPDX-License-Identifier: MPL-2.0

#![short_vis_path::add(procfs)]

use super::PidDirOps;
use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            StaticEntryWithOps,
            pid::task::{
                auxv::AuxvFileOps, cgroup::CgroupFileOps, children::ChildrenFileOps,
                cmdline::CmdlineFileOps, comm::CommFileOps, environ::EnvironFileOps,
                exe::ExeSymOps, fd::FdDirOps, fs_links::FsLinkOps, gid_map::GidMapFileOps,
                maps::MapsFileOps, mem::MemFileOps, mountinfo::MountInfoFileOps,
                mounts::MountsFileOps, mountstats::MountStatsFileOps, ns::NsDirOps,
                oom_score_adj::OomScoreAdjFileOps, setgroups::SetgroupsFileOps, stat::StatFileOps,
                statm::StatmFileOps, status::StatusFileOps, uid_map::UidMapFileOps,
                wchan::WchanFileOps,
            },
            template::{
                ListedEntry, ProcDir, ProcDirOps, ReaddirEntry, keyed_readdir_entries,
                listed_entries_from_table, lookup_child_from_table, visit_listed_entries,
                visit_readdir_entries,
            },
        },
        vfs::inode::{Inode, RevalidationPolicy},
    },
    prelude::*,
    process::{Process, posix_thread::AsPosixThread},
    thread::{AsThread, Thread, Tid},
};

mod auxv;
mod cgroup;
mod children;
mod cmdline;
mod comm;
mod environ;
mod exe;
mod fd;
mod fs_links;
mod gid_map;
mod maps;
mod mem;
mod mountinfo;
mod mounts;
mod mountstats;
mod ns;
mod oom_score_adj;
mod setgroups;
pub(super) mod stat;
mod statm;
mod status;
mod uid_map;
mod wchan;

/// Represents the inode at `/proc/[pid]/task`.
pub(super) struct TaskDirOps(Arc<Process>);

impl TaskDirOps {
    pub(super) fn new_inode(dir: &PidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3316>
        ProcDir::new(Self(dir.process().clone()), parent, mkmod!(a+rx))
    }

    fn process(&self) -> Option<Arc<Process>> {
        Some(self.0.clone())
    }
}

/// Represents the inode at `/proc/[pid]/task/[tid]`.
#[derive(Clone)]
pub(in procfs) struct TidDirOps {
    process: Arc<Process>,
    /// If `thread` is `None`, this corresponds to a process-level `/proc/[pid]/*` file.
    /// Otherwise, this corresponds to a thread-level `/proc/[pid]/task/[tid]/*` file.
    thread: Option<Arc<Thread>>,
}

impl TidDirOps {
    pub(super) fn new(process: Arc<Process>, thread: Option<Arc<Thread>>) -> Self {
        Self { process, thread }
    }

    pub(in procfs) fn new_inode(
        process: Arc<Process>,
        thread: Arc<Thread>,
        parent: Weak<dyn Inode>,
    ) -> Arc<dyn Inode> {
        ProcDir::new(
            Self {
                process,
                thread: Some(thread),
            },
            parent,
            // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3796>
            mkmod!(a+rx),
        )
    }

    pub(in procfs) fn process(&self) -> &Arc<Process> {
        &self.process
    }

    pub(in procfs) fn thread(&self) -> Option<Arc<Thread>> {
        Some(
            self.thread
                .clone()
                .unwrap_or_else(|| self.process.main_thread()),
        )
    }

    pub(in procfs) fn thread_and_process(&self) -> Option<(Arc<Thread>, Arc<Process>)> {
        Some((self.thread()?, self.process.clone()))
    }

    const TASK_ONLY_ENTRIES: &'static [StaticEntryWithOps<TidDirOps>] = &[
        ("children", InodeType::File, ChildrenFileOps::new_inode),
    ];

    const STATIC_ENTRIES: &'static [StaticEntryWithOps<TidDirOps>] = &[
        ("auxv", InodeType::File, AuxvFileOps::new_inode),
        ("cgroup", InodeType::File, CgroupFileOps::new_inode),
        ("cmdline", InodeType::File, CmdlineFileOps::new_inode),
        ("comm", InodeType::File, CommFileOps::new_inode),
        ("environ", InodeType::File, EnvironFileOps::new_inode),
        ("cwd", InodeType::SymLink, FsLinkOps::new_cwd_inode),
        ("root", InodeType::SymLink, FsLinkOps::new_root_inode),
        ("exe", InodeType::SymLink, ExeSymOps::new_inode),
        ("fd", InodeType::Dir, FdDirOps::<fd::FileSymOps>::new_inode),
        (
            "fdinfo",
            InodeType::Dir,
            FdDirOps::<fd::FileInfoOps>::new_inode,
        ),
        ("gid_map", InodeType::File, GidMapFileOps::new_inode),
        ("mem", InodeType::File, MemFileOps::new_inode),
        ("mountinfo", InodeType::File, MountInfoFileOps::new_inode),
        ("mountstats", InodeType::File, MountStatsFileOps::new_inode),
        ("ns", InodeType::Dir, NsDirOps::new_inode),
        (
            "oom_score_adj",
            InodeType::File,
            OomScoreAdjFileOps::new_inode,
        ),
        ("setgroups", InodeType::File, SetgroupsFileOps::new_inode),
        ("stat", InodeType::File, StatFileOps::new_thread_inode),
        ("statm", InodeType::File, StatmFileOps::new_inode),
        ("status", InodeType::File, StatusFileOps::new_inode),
        ("uid_map", InodeType::File, UidMapFileOps::new_inode),
        ("wchan", InodeType::File, WchanFileOps::new_inode),
        ("maps", InodeType::File, MapsFileOps::new_inode),
        ("mounts", InodeType::File, MountsFileOps::new_inode),
    ];
}

impl ProcDirOps for TidDirOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.thread()
    }

    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        if !self.is_valid() {
            return Err(errno!(ENOENT, "the thread or the process does not exist"));
        };

        if let Some(child) = lookup_child_from_table(name, Self::TASK_ONLY_ENTRIES, |f| {
            (f)(self, this_dir.this_weak().clone())
        }) {
            return Ok(child);
        }

        self.lookup_static_child(this_dir.this_weak().clone(), name)
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        if !self.is_valid() {
            return Err(errno!(ENOENT, "the thread or the process does not exist"));
        };

        let entries = self
            .static_listed_entries()
            .chain(listed_entries_from_table(Self::TASK_ONLY_ENTRIES));
        visit_listed_entries(offset, entries, visit_fn)
    }

    fn revalidation_policy(&self) -> RevalidationPolicy {
        RevalidationPolicy::REVALIDATE_EXISTS
    }

    fn revalidate_exists(&self, _name: &str, _child: &dyn Inode) -> bool {
        self.is_valid()
    }
}

impl TidDirOps {
    /// Returns whether the thread or process backing this directory is still observable.
    ///
    /// The check is performed from the viewer's PID namespace so that dentries cached
    /// by one namespace are not wrongly reused by another.
    pub(super) fn is_valid(&self) -> bool {
        let viewer = current!();
        let viewer_pid_ns = viewer.active_pid_ns();
        if let Some(thread) = self.thread.as_ref() {
            thread
                .as_posix_thread()
                .unwrap()
                .tid_in(viewer_pid_ns)
                .and_then(|tid| viewer_pid_ns.lookup_thread(tid))
                .is_some_and(|target| Arc::ptr_eq(&target, thread))
        } else {
            self.process
                .pid_in(viewer_pid_ns)
                .and_then(|pid| viewer_pid_ns.lookup_process(pid))
                .is_some_and(|target| Arc::ptr_eq(&target, &self.process))
        }
    }

    pub(super) fn lookup_static_child(
        &self,
        this_ptr: Weak<dyn Inode>,
        name: &str,
    ) -> Result<Arc<dyn Inode>> {
        if let Some(child) =
            lookup_child_from_table(name, Self::STATIC_ENTRIES, |f| (f)(self, this_ptr))
        {
            return Ok(child);
        }

        Err(errno!(ENOENT, "the file does not exist"))
    }

    pub(super) fn static_listed_entries(&self) -> impl Iterator<Item = ListedEntry<'_>> + '_ {
        listed_entries_from_table(Self::STATIC_ENTRIES)
    }
}

impl ProcDirOps for TaskDirOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        Some(self.0.main_thread())
    }

    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        let Ok(tid) = name.parse::<Tid>() else {
            return Err(errno!(ENOENT, "the name is not a valid TID"));
        };

        let Some(process) = self.process() else {
            return Err(errno!(ESRCH, "the process does not exist"));
        };

        // TIDs in `/proc/[pid]/task` are resolved from the viewer's PID namespace.
        // The viewer is the process performing the lookup.
        let viewer = current!();
        let viewer_pid_ns = viewer.active_pid_ns();

        for task in process.tasks().lock().as_slice() {
            let thread = task.as_thread().unwrap();
            if thread.as_posix_thread().unwrap().tid_in(viewer_pid_ns) != Some(tid) {
                continue;
            }
            return Ok(TidDirOps::new_inode(
                process.clone(),
                thread.clone(),
                this_dir.this_weak().clone(),
            ));
        }

        Err(errno!(ENOENT, "the thread does not exist"))
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        let Some(process) = self.process() else {
            return Err(errno!(ENOENT, "the process does not exist"));
        };

        let viewer = current!();
        let viewer_pid_ns = viewer.active_pid_ns();

        // Collect TIDs before visiting entries, as `visit_fn` may copy data to user memory.
        let tids = process
            .tasks()
            .lock()
            .as_slice()
            .iter()
            .filter_map(|task| {
                let tid = task.as_posix_thread().unwrap().tid_in(viewer_pid_ns)?;
                usize::try_from(tid).ok()
            })
            .collect::<Vec<_>>();

        visit_readdir_entries(
            keyed_readdir_entries(offset, 2, tids, |tid| {
                ListedEntry::new(tid.to_string(), InodeType::Dir)
            }),
            visit_fn,
        )
    }

    fn revalidation_policy(&self) -> RevalidationPolicy {
        RevalidationPolicy::REVALIDATE_EXISTS | RevalidationPolicy::REVALIDATE_ABSENT
    }

    fn revalidate_exists(&self, name: &str, child: &dyn Inode) -> bool {
        let Ok(tid) = name.parse::<Tid>() else {
            // For non-numeric names, the set of valid children does not change over time,
            // so we can rely on the cache without revalidating.
            return true;
        };

        let Some(child) = child.downcast_ref::<ProcDir<TidDirOps>>() else {
            return false;
        };

        let viewer = current!();
        let viewer_pid_ns = viewer.active_pid_ns();
        let child_ops = child.inner();
        // The cached thread must be the task of the same process
        // and still carry this TID in the viewer's namespace.
        if !Arc::ptr_eq(child_ops.process(), &self.0) {
            return false;
        }
        child_ops
            .thread
            .as_ref()
            .and_then(|thread| thread.as_posix_thread().unwrap().tid_in(viewer_pid_ns))
            == Some(tid)
    }

    fn revalidate_absent(&self, name: &str) -> bool {
        let Ok(tid) = name.parse::<Tid>() else {
            return true;
        };

        let Some(process) = self.process() else {
            return true;
        };

        let viewer = current!();
        let viewer_pid_ns = viewer.active_pid_ns();
        process
            .tasks()
            .lock()
            .as_slice()
            .iter()
            .all(|task| {
                task.as_posix_thread().unwrap().tid_in(viewer_pid_ns) != Some(tid)
            })
    }
}
