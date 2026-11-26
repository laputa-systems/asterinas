// SPDX-License-Identifier: MPL-2.0

// Tests for seccomp installation validation: argument checks, the
// no-new-privs requirement, strict-mode transitions, and action queries.

#define _GNU_SOURCE

#include "../common/test.h"
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1U << 4)
#endif
#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1U << 2)
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_KILL_THREAD 0x00000000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP 0x00030000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_TRACE
#define SECCOMP_RET_TRACE 0x7ff00000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

#define NOBODY_UID 65534

static struct sock_filter allow_all[] = {
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static int install(unsigned int flags, struct sock_filter *filter,
		   unsigned int len)
{
	struct sock_fprog prog = {
		.len = (unsigned short)len,
		.filter = filter,
	};
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog);
}

static int child_status(pid_t pid)
{
	int status = 0;
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && WIFEXITED(status));
	return WEXITSTATUS(status);
}

FN_TEST(null_and_flags)
{
	// NULL programs fail with EFAULT, even with TSYNC (mirrors the
	// Chromium sandbox probes). Bad flags and operations fail with EINVAL.
	TEST_ERRNO(
		syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			SECCOMP_FILTER_FLAG_TSYNC, NULL),
		EFAULT);
	TEST_ERRNO(
		syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, NULL),
		EFAULT);
	TEST_ERRNO(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL, 0, 0),
		   EFAULT);
	TEST_ERRNO(install(0x100, allow_all, 1), EINVAL);
	TEST_ERRNO(install(0x20, allow_all, 1), EINVAL);
	TEST_ERRNO(syscall(SYS_seccomp, 99, 0, allow_all), EINVAL);
	TEST_ERRNO(syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 1, NULL),
		   EINVAL);
	TEST_ERRNO(syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0,
			   (void *)1),
		   EINVAL);
}
END_TEST()

FN_TEST(requires_nnp)
{
	// Installing a filter without no-new-privs fails with EACCES for
	// unprivileged users.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		if (getuid() == 0) {
			if (setgid(NOBODY_UID) != 0 || setuid(NOBODY_UID) != 0)
				_exit(2);
		}
		if (getuid() == 0)
			_exit(3);
		if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0)
			_exit(4);
		errno = 0;
		if (install(0, allow_all, 1) == 0 ||
		    errno != EACCES)
			_exit(5);
		// With no-new-privs, the same program installs cleanly.
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
			_exit(6);
		if (install(0, allow_all, 1) != 0)
			_exit(7);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(rejects_malformed_programs)
{
	// Each malformed program is installed in a fresh child so one
	// rejection does not affect the others.
	struct sock_filter out_of_range[] = {
		BPF_STMT(BPF_JMP | BPF_JA, 50),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_filter no_return[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
	};
	struct sock_filter misaligned[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 3),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_filter beyond[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 sizeof(struct seccomp_data)),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	pid_t pid = CHECK(fork());
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
			_exit(2);
		if (install(0, out_of_range, 2) == 0 || errno != EINVAL)
			_exit(10);
		if (install(0, no_return, 1) == 0 || errno != EINVAL)
			_exit(11);
		if (install(0, misaligned, 2) == 0 || errno != EINVAL)
			_exit(12);
		if (install(0, beyond, 2) == 0 || errno != EINVAL)
			_exit(13);
		if (install(0, out_of_range, 0) == 0 || errno != EINVAL)
			_exit(14);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(strict_transitions)
{
	// Once filters are installed, strict mode is unreachable. Strict mode
	// itself can only be entered with zero flags and a NULL program.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
			_exit(2);
		if (install(0, allow_all, 1) != 0)
			_exit(3);
		errno = 0;
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0,
			    NULL) == 0 ||
		    errno != EINVAL)
			_exit(4);
		errno = 0;
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, NULL, 0, 0) ==
			    0 ||
		    errno != EINVAL)
			_exit(5);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(action_avail)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
			_exit(2);
		uint32_t actions[] = {
			SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD,
			SECCOMP_RET_TRAP,	  SECCOMP_RET_ERRNO,
			SECCOMP_RET_TRACE,	  SECCOMP_RET_LOG,
			SECCOMP_RET_ALLOW,
		};
		for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]);
		     i++) {
			errno = 0;
			if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
				    &actions[i]) != 0)
				_exit(10 + (int)i);
		}
		// Unknown or data-carrying actions are not available.
		uint32_t unknown = 0x12340000;
		errno = 0;
		if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
			    &unknown) == 0 ||
		    errno != EOPNOTSUPP)
			_exit(20);
		uint32_t data_bits = SECCOMP_RET_ALLOW | 1;
		errno = 0;
		if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
			    &data_bits) == 0 ||
		    errno != EOPNOTSUPP)
			_exit(21);
		uint32_t notif = SECCOMP_RET_USER_NOTIF;
		errno = 0;
		if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
			    &notif) == 0 ||
		    errno != EOPNOTSUPP)
			_exit(22);
		// Non-zero query flags are invalid.
		uint32_t allow = SECCOMP_RET_ALLOW;
		errno = 0;
		if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 1,
			    &allow) == 0 ||
		    errno != EINVAL)
			_exit(23);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()
