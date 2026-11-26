// SPDX-License-Identifier: MPL-2.0

use crate::{
    fs::file::file_table::FileTable,
    prelude::*,
    process::{
        CloneFlags, PidNamespace, PidNsForChildren, UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::ContextPthreadAdminApi,
    },
    security::lsm::hooks as lsm_hooks,
};

/// Provides administrative APIs for disassociating execution contexts.
pub(crate) trait ContextUnshareAdminApi {
    /// Unshares the file table.
    fn unshare_files(&self);
    /// Unshares filesystem attributes.
    fn unshare_fs(&self);
    /// Unshares System V semaphore.
    fn unshare_sysvsem(&self);
    /// Creates and enters new namespaces as specified by the `flags` argument.
    fn unshare_namespaces(&self, flags: CloneFlags) -> Result<()>;
}

impl ContextUnshareAdminApi for Context<'_> {
    fn unshare_files(&self) {
        let mut pthread_file_table = self.posix_thread.file_table().lock();
        let mut thread_local_file_table = self.thread_local.borrow_file_table_mut();

        let new_file_table = FileTable::fork_from(&thread_local_file_table.read());

        *pthread_file_table = Some(new_file_table.clone_ro());
        *thread_local_file_table = new_file_table;
    }

    fn unshare_fs(&self) {
        let mut fs_ref = self.thread_local.borrow_fs_mut();
        let new_fs = fs_ref.as_ref().clone();
        *fs_ref = Arc::new(new_fs);
        self.posix_thread.set_fs(fs_ref.clone());
    }

    fn unshare_sysvsem(&self) {
        // TODO: Support unsharing System V semaphore.
        warn!("unsharing System V semaphore is not supported");
    }

    fn unshare_namespaces(&self, flags: CloneFlags) -> Result<()> {
        // Creating a new user namespace never requires privileges,
        // mirroring unprivileged user namespace creation in Linux.
        // The new namespace starts out with empty ID maps; IDs observed
        // through it translate to the overflow IDs until maps are written.
        let new_user_ns = if flags.contains(CloneFlags::CLONE_NEWUSER) {
            let parent_ns = self.thread_local.borrow_user_ns().clone();
            let euid = self.posix_thread.credentials().euid();
            Some(UserNamespace::new_child(&parent_ns, euid)?)
        } else {
            None
        };

        let mut remaining_flags = flags;

        if flags.contains(CloneFlags::CLONE_NEWPID) {
            let user_ns = self.thread_local.borrow_user_ns();
            lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
                user_ns.as_ref(),
                self.posix_thread,
                CapSet::SYS_ADMIN,
            ))?;

            let mut pid_ns_for_children = self.posix_thread.pid_ns_for_children().lock();
            if !matches!(&*pid_ns_for_children, PidNsForChildren::SameAsActive) {
                return Err(errno!(
                    EINVAL,
                    "the pid-for-children namespace is already pending"
                ));
            }

            let new_pid_ns =
                PidNamespace::new_child(self.process.active_pid_ns().clone(), user_ns.clone())?;
            *pid_ns_for_children = PidNsForChildren::Target(new_pid_ns);
            remaining_flags.remove(CloneFlags::CLONE_NEWPID);
        }

        if remaining_flags.is_empty() {
            return Ok(());
        }

        let user_ns_ref = match new_user_ns.as_ref() {
            Some(new_user_ns) => new_user_ns.clone(),
            None => self.thread_local.borrow_user_ns().clone(),
        };

        let mut pthread_ns_proxy = self.posix_thread.ns_proxy().lock();
        let mut thread_local_ns_proxy = self.thread_local.borrow_ns_proxy_mut();

        let new_ns_proxy = thread_local_ns_proxy.new_clone(
            &user_ns_ref,
            self.process.as_ref(),
            self.posix_thread,
            remaining_flags,
        )?;

        if remaining_flags.contains(CloneFlags::CLONE_NEWNS) {
            self.thread_local
                .borrow_fs()
                .resolver()
                .write()
                .switch_to_mnt_ns(new_ns_proxy.mnt_ns())?;
        }

        *pthread_ns_proxy = Some(new_ns_proxy.clone());
        *thread_local_ns_proxy = new_ns_proxy;

        if let Some(new_user_ns) = new_user_ns {
            // Entering a new user namespace grants the full set of capabilities
            // within that namespace, mirroring Linux.
            *self.process.user_ns().lock() = new_user_ns.clone();
            self.thread_local.set_user_ns(new_user_ns);
            let credentials = self.credentials_mut();
            credentials.set_permitted_capset(CapSet::all());
            credentials.set_effective_capset(CapSet::all());
        }

        Ok(())
    }
}
