// SPDX-License-Identifier: MPL-2.0

// Tests for SECCOMP_RET_TRAP: the SIGSYS handler observes the Linux siginfo
// fields and overrides the syscall return value; a blocked SIGSYS kills the
// thread with SIGSYS instead.

#define _GNU_SOURCE

#include "../common/test.h"
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP 0x00030000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#if defined(__x86_64__)
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_X86_64
#endif

#define TRAPPED_RESULT 4242

static int child_status(pid_t pid)
{
	int status = 0;
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1000 + status;
}

static volatile sig_atomic_t trapped_syscall = -1;
static volatile sig_atomic_t trapped_ok;
static volatile unsigned long trapped_ra;
static volatile sig_atomic_t trapped_rip_ok;

static void on_sigsys(int sig, siginfo_t *info, void *ctx)
{
	(void)sig;
	ucontext_t *uc = ctx;
	trapped_syscall = info->si_syscall;
	trapped_ok = info->si_code == 1 /* SYS_SECCOMP */ &&
		     info->si_arch == AUDIT_ARCH_NATIVE;
#if defined(__x86_64__)
	trapped_ra = uc->uc_mcontext.gregs[REG_RAX];
	trapped_rip_ok =
		uc->uc_mcontext.gregs[REG_RIP] == (long)(uintptr_t)info->si_call_addr;
	uc->uc_mcontext.gregs[REG_RAX] = TRAPPED_RESULT;
#else
	trapped_ra = uc->uc_mcontext.regs[0];
	trapped_rip_ok =
		uc->uc_mcontext.pc == (uintptr_t)info->si_call_addr;
	uc->uc_mcontext.regs[0] = TRAPPED_RESULT;
#endif
}

FN_TEST(trap_handler)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sigaction sa = { .sa_sigaction = on_sigsys,
					.sa_flags = SA_SIGINFO };
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGSYS, &sa, NULL) != 0)
			_exit(2);
		struct sock_filter filter[] = {
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_uname, 0,
				 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		};
		struct sock_fprog prog = { 4, filter };
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
			_exit(3);
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
			    &prog) != 0)
			_exit(4);
		struct utsname u;
		errno = 0;
		long trapped = syscall(SYS_uname, &u);
#if defined(__x86_64__)
		uintptr_t expected_ra = SYS_uname;
#else
		uintptr_t expected_ra = (uintptr_t)&u;
#endif
		if (trapped != TRAPPED_RESULT)
			_exit(5);
		if (trapped_syscall != SYS_uname || !trapped_ok ||
		    trapped_ra != expected_ra || !trapped_rip_ok)
			_exit(6);
		// Unfiltered syscalls still run normally.
		if (getpid() <= 0)
			_exit(7);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(trap_blocked)
{
	// A blocked SIGSYS cannot suppress the trap: the thread dies with
	// SIGSYS instead of running the handler.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sigaction sa = { .sa_sigaction = on_sigsys,
					.sa_flags = SA_SIGINFO };
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGSYS, &sa, NULL) != 0)
			_exit(2);
		sigset_t mask;
		sigemptyset(&mask);
		sigaddset(&mask, SIGSYS);
		if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0)
			_exit(3);
		struct sock_filter filter[] = {
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_uname, 0,
				 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		};
		struct sock_fprog prog = { 4, filter };
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
			_exit(4);
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
			    &prog) != 0)
			_exit(5);
		struct utsname u;
		trapped_syscall = -1;
		long trapped = syscall(SYS_uname, &u);
		_exit(trapped == TRAPPED_RESULT &&
				      trapped_syscall == SYS_uname ?
			      0 :
			      6);
	}
	int status = 0;
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
	TEST_RES(0, WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS);
}
END_TEST()
