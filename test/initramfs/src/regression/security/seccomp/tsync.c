// SPDX-License-Identifier: MPL-2.0

// Tests for SECCOMP_FILTER_FLAG_TSYNC: a synchronized filter reaches every
// thread, and incompatible threads are reported (or yield ESRCH with
// SECCOMP_FILTER_FLAG_TSYNC_ESRCH).

#define _GNU_SOURCE

#include "../common/test.h"
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1U << 4)
#endif

static void deny_socket(struct sock_filter *filter, uint32_t action)
{
	filter[0] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			     offsetof(struct seccomp_data, nr));
	filter[1] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 1);
	filter[2] = BPF_STMT(BPF_RET | BPF_K, action);
	filter[3] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

static int child_status(pid_t pid)
{
	int status = 0;
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1000 + status;
}

static volatile int worker_ready;
static volatile int worker_go;
static volatile int worker_errno;

static void *deny_check_worker(void *arg)
{
	(void)arg;
	worker_ready = 1;
	while (!worker_go) {
		struct timespec ts = { 0, 1000000 };
		nanosleep(&ts, NULL);
	}
	errno = 0;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	worker_errno = (fd < 0 ? errno : 0);
	return NULL;
}

FN_TEST(tsync_success)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
			_exit(2);
		worker_ready = 0;
		worker_go = 0;
		worker_errno = 0;
		pthread_t thread;
		if (pthread_create(&thread, NULL, deny_check_worker, NULL) !=
		    0)
			_exit(3);
		while (!worker_ready) {
			struct timespec ts = { 0, 1000000 };
			nanosleep(&ts, NULL);
		}
		struct sock_filter filter[4];
		deny_socket(filter, SECCOMP_RET_ERRNO | EACCES);
		struct sock_fprog prog = { 4, filter };
		errno = 0;
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			    SECCOMP_FILTER_FLAG_TSYNC, &prog) != 0)
			_exit(4);
		worker_go = 1;
		pthread_join(thread, NULL);
		errno = 0;
		int main_denied = socket(AF_INET, SOCK_STREAM, 0) < 0 &&
				  errno == EACCES;
		_exit(worker_errno == EACCES && main_denied ? 0 : 5);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

static volatile int divergent_ready;
static volatile int divergent_go;

static void *divergent_worker(void *arg)
{
	(void)arg;
	struct sock_filter filter[4];
	deny_socket(filter, SECCOMP_RET_ERRNO | E2BIG);
	struct sock_fprog prog = { 4, filter };
	syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
	divergent_ready = 1;
	while (!divergent_go) {
		struct timespec ts = { 0, 1000000 };
		nanosleep(&ts, NULL);
	}
	return NULL;
}

static int run_divergent(unsigned int extra_flags, int want_esrch)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		return 2;
	struct sock_filter base[] = {
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog baseprog = { 1, base };
	if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &baseprog) != 0)
		return 3;
	divergent_ready = 0;
	divergent_go = 0;
	pthread_t thread;
	if (pthread_create(&thread, NULL, divergent_worker, NULL) != 0)
		return 4;
	while (!divergent_ready) {
		struct timespec ts = { 0, 1000000 };
		nanosleep(&ts, NULL);
	}
	struct sock_filter filter[4];
	deny_socket(filter, SECCOMP_RET_ERRNO | EACCES);
	struct sock_fprog prog = { 4, filter };
	errno = 0;
	long ret = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			   SECCOMP_FILTER_FLAG_TSYNC | extra_flags, &prog);
	divergent_go = 1;
	pthread_join(thread, NULL);
	if (want_esrch)
		return (ret < 0 && errno == ESRCH) ? 0 : 5;
	return ret > 0 ? 0 : 6;
}

FN_TEST(tsync_divergent)
{
	pid_t pid = CHECK(fork());
	if (pid == 0)
		_exit(run_divergent(0, 0));
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(tsync_esrch)
{
	pid_t pid = CHECK(fork());
	if (pid == 0)
		_exit(run_divergent(SECCOMP_FILTER_FLAG_TSYNC_ESRCH, 1));
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()

FN_TEST(tsync_spec_allow)
{
	// SPEC_ALLOW filters install like ordinary filters.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
			_exit(2);
		struct sock_filter filter[4];
		deny_socket(filter, SECCOMP_RET_ERRNO | EACCES);
		struct sock_fprog prog = { 4, filter };
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			    SECCOMP_FILTER_FLAG_SPEC_ALLOW, &prog) != 0)
			_exit(3);
		errno = 0;
		if (socket(AF_INET, SOCK_STREAM, 0) >= 0 || errno != EACCES)
			_exit(4);
		_exit(0);
	}
	TEST_RES(child_status(pid), _ret == 0);
}
END_TEST()
