// SPDX-License-Identifier: MPL-2.0

// Tests for seccomp filter enforcement: ERRNO actions (including the errno
// cap), stacking precedence, inheritance across fork/clone/exec, kill
// actions, strict mode, and the procfs status fields.

#define _GNU_SOURCE

#include "../common/test.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

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
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif

static int install(struct sock_filter *filter, unsigned int len)
{
	struct sock_fprog prog = {
		.len = (unsigned short)len,
		.filter = filter,
	};
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		return -errno;
	if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0)
		return -errno;
	return 0;
}

static int child_status(pid_t pid)
{
	int status = 0;
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1000 + status;
}

static void deny_socket(struct sock_filter *filter, uint32_t action)
{
	filter[0] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			       offsetof(struct seccomp_data, nr));
	filter[1] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 1);
	filter[2] = BPF_STMT(BPF_RET | BPF_K, action);
	filter[3] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

FN_TEST(errno_action)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sock_filter filter[4];
		deny_socket(filter, SECCOMP_RET_ERRNO | EACCES);
		if (install(filter, 4) != 0)
			_exit(2);
		errno = 0;
		if (socket(AF_INET, SOCK_STREAM, 0) >= 0 || errno != EACCES)
			_exit(3);
		// Unfiltered syscalls keep working.
		if (getpid() <= 0)
			_exit(4);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(errno_capped)
{
	// Errno values above 4095 are capped, matching Linux's MAX_ERRNO.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sock_filter filter[4];
		deny_socket(filter, SECCOMP_RET_ERRNO | 5000);
		if (install(filter, 4) != 0)
			_exit(2);
		errno = 0;
		if (socket(AF_INET, SOCK_STREAM, 0) >= 0 || errno != 4095)
			_exit(3);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(stacking)
{
	// A deny filter installed first is not overridden by a later
	// allow-all filter.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sock_filter deny[4], allow[1];
		deny_socket(deny, SECCOMP_RET_ERRNO | EACCES);
		allow[0] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
		if (install(deny, 4) != 0)
			_exit(2);
		struct sock_fprog prog = { 1, allow };
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
			    &prog) != 0)
			_exit(3);
		errno = 0;
		if (socket(AF_INET, SOCK_STREAM, 0) >= 0 || errno != EACCES)
			_exit(4);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(inherit_fork)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sock_filter filter[4];
		deny_socket(filter, SECCOMP_RET_ERRNO | EACCES);
		if (install(filter, 4) != 0)
			_exit(2);
		pid_t child = fork();
		if (child < 0)
			_exit(3);
		if (child == 0) {
			errno = 0;
			_exit(socket(AF_INET, SOCK_STREAM, 0) < 0 &&
				       errno == EACCES ?
				      0 :
				      1);
		}
		_exit(child_status(child) == 0 ? 0 : 4);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(kill_thread)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sock_filter filter[4] = {
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_uname, 0,
				 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_THREAD),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		};
		if (install(filter, 4) != 0)
			_exit(2);
		// Only the calling thread dies; the process survives.
		pid_t child = fork();
		if (child < 0)
			_exit(3);
		if (child == 0) {
			struct utsname u;
			syscall(SYS_uname, &u);
			_exit(4);
		}
		int status = 0;
		if (waitpid(child, &status, 0) != child ||
		    !WIFSIGNALED(status) || WTERMSIG(status) != SIGSYS)
			_exit(5);
		_exit(getpid() > 0 ? 0 : 6);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(kill_process)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sock_filter filter[4] = {
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0,
				 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		};
		if (install(filter, 4) != 0)
			_exit(2);
		getpid();
		_exit(3);
	}
	int status = 0;
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
	TEST_RES(0, WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS);
}
END_TEST()

FN_TEST(strict_mode)
{
	// Under strict mode only read, write, _exit and rt_sigreturn are
	// allowed. Other syscalls kill the process with SIGKILL.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL) !=
		    0)
			_exit(2);
		if (syscall(SYS_write, STDOUT_FILENO, "", 0) != 0)
			_exit(3);
		syscall(SYS_exit, 0);
		_exit(4);
	}
	int status = 0;
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
	TEST_RES(0, WIFEXITED(status) && WEXITSTATUS(status) == 0);

	pid = CHECK(fork());
	if (pid == 0) {
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL) !=
		    0)
			_exit(2);
		getpid();
		_exit(3);
	}
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
	TEST_RES(0, WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}
END_TEST()

FN_TEST(proc_status)
{
	// The mode and filter count are visible in /proc/self/status.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sock_filter filter[4];
		deny_socket(filter, SECCOMP_RET_ERRNO | EACCES);
		if (install(filter, 4) != 0)
			_exit(2);
		if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2)
			_exit(3);
		char text[4096];
		int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			_exit(4);
		ssize_t got = 0, n;
		while (got < (ssize_t)sizeof(text) - 1 &&
		       (n = read(fd, text + got,
				 sizeof(text) - 1 - (size_t)got)) > 0)
			got += n;
		close(fd);
		text[got] = '\0';
		if (!strstr(text, "Seccomp:\t2\n"))
			_exit(5);
		if (!strstr(text, "Seccomp_filters:\t1\n"))
			_exit(6);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()
