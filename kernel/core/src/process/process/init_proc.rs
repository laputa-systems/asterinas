// SPDX-License-Identifier: MPL-2.0

//! This module defines functions related to spawning the init process.

use ostd::{arch::cpu::context::UserContext, cpu::CpuSet, task::Task, user::UserContextApi};

use super::{Process, Session};
use crate::{
    fs::{
        thread_info::ThreadFsInfo,
        vfs::path::{Path, PathResolver},
    },
    prelude::*,
    process::{
        Credentials, KernelTid, PidChain, PidNamespace, PidNsForChildren, ProcessVm,
        ShebangScriptPath, UndetectedExecutable, UserNamespace,
        namespace::pid_ns::pid_ns_graph_lock,
        posix_thread::{PosixThreadBuilder, allocate_posix_tid, derive_thread_name},
        program_loader::ProgramToLoad,
        rlimit::new_resource_limits_for_init,
        signal::sig_disposition::SigDispositions,
    },
    thread::AsThread,
    vm::vmar::VmarHandle,
};

/// Creates and schedules the init process to run.
pub(crate) fn spawn_init_process(
    path_resolver: PathResolver,
    executable_path: Path,
    argv: Vec<CString>,
    envp: Vec<CString>,
) -> Result<Arc<Process>> {
    let process = create_init_process(path_resolver, executable_path, argv, envp)?;

    // Linux starts the init process without placing it in a process group or session.
    // It joins one only after userspace first calls `setsid()`.
    //
    // Asterinas instead requires every process to belong to both a process group and
    // a session. The init process is therefore placed in a bootstrap process group
    // and session with PGID and SID set to zero. This preserves the same user-visible
    // behavior.
    set_bootstrap_session_and_group(&process);

    process.run();

    Ok(process)
}

fn create_init_process(
    path_resolver: PathResolver,
    executable_path: Path,
    argv: Vec<CString>,
    envp: Vec<CString>,
) -> Result<Arc<Process>> {
    let fs = ThreadFsInfo::new(path_resolver);

    let root_pid_ns = PidNamespace::get_init_singleton().clone();
    let pid_chain = PidChain::one(root_pid_ns.clone(), 1);
    let kernel_tid = allocate_posix_tid();
    let vmar = VmarHandle::new(ProcessVm::new(executable_path.clone()));
    let resource_limits = new_resource_limits_for_init();
    let oom_score_adj = 0;
    let sig_dispositions = Arc::new(Mutex::new(SigDispositions::default()));
    let user_ns = UserNamespace::get_init_singleton().clone();

    let init_proc = Process::new(
        kernel_tid,
        pid_chain.clone(),
        root_pid_ns.clone(),
        vmar.clone_arc(),
        resource_limits,
        oom_score_adj,
        sig_dispositions,
        user_ns,
    );

    let init_task = create_init_task(
        kernel_tid,
        pid_chain,
        &init_proc,
        fs,
        vmar,
        executable_path,
        argv,
        envp,
    )?;
    init_proc.tasks().lock().insert(init_task).unwrap();
    root_pid_ns.set_child_reaper(&init_proc);

    Ok(init_proc)
}

fn set_bootstrap_session_and_group(process: &Arc<Process>) {
    let _pid_ns_graph_guard = pid_ns_graph_lock().lock();

    // Add the process to the bootstrap process group and session.
    let (session, process_group) = Session::new_bootstrap_pair(process);
    PidNamespace::insert_session_across_namespaces_with_pid_ns_graph_lock(session);
    PidNamespace::insert_process_group_across_namespaces_with_pid_ns_graph_lock(
        process_group.clone(),
    );
    *process.process_group.lock() = Some(process_group);

    // Add the new process to the per-namespace tables.
    PidNamespace::insert_process_across_namespaces_with_pid_ns_graph_lock(process.clone());
    let init_thread = process
        .tasks()
        .lock()
        .main()
        .as_thread()
        .unwrap()
        .clone();
    PidNamespace::insert_thread_across_namespaces_with_pid_ns_graph_lock(init_thread);
}

/// Creates the init task from the given executable path.
#[expect(clippy::too_many_arguments)]
fn create_init_task(
    kernel_tid: KernelTid,
    pid_chain: PidChain,
    process: &Arc<Process>,
    fs: ThreadFsInfo,
    vmar: VmarHandle,
    executable_path: Path,
    argv: Vec<CString>,
    envp: Vec<CString>,
) -> Result<Arc<Task>> {
    let credentials = Credentials::new_root();

    let (elf_load_info, executable_abs_path) = {
        let path_resolver = fs.resolver().read();
        let executable_abs_path = path_resolver.make_abs_path(&executable_path).into_string();
        let shebang_script_path =
            ShebangScriptPath::Accessible(CString::new(executable_abs_path.clone()).unwrap());

        let executable = UndetectedExecutable::open(executable_path.clone(), shebang_script_path)?;
        let program_to_load =
            ProgramToLoad::from_executable(executable, &path_resolver, argv, envp)?;
        let vmar = process.lock_vmar();
        let elf_load_info = program_to_load.load_to_vmar(vmar.unwrap(), &path_resolver)?;

        (elf_load_info, executable_abs_path)
    };

    let mut user_ctx = UserContext::default();
    user_ctx.set_instruction_pointer(elf_load_info.entry_point as _);
    user_ctx.set_stack_pointer(elf_load_info.user_stack_top as _);

    let thread_name = derive_thread_name(&executable_abs_path);

    let thread_builder = PosixThreadBuilder::new(
        kernel_tid,
        pid_chain,
        thread_name,
        Box::new(user_ctx),
        credentials,
        vmar,
        CpuSet::new_full(),
    )
    .process(Arc::downgrade(process))
    .fs(Arc::new(fs))
    .pid_ns_for_children(PidNsForChildren::SameAsActive);
    Ok(thread_builder.build())
}
