// SPDX-License-Identifier: MPL-2.0

// Tests that a robust mutex left locked by an exiting process wakes a locker
// with EOWNERDEAD, and that cyclic robust lists do not hang thread exit.

#include "../../common/test.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

FN_TEST(robust_owner_dies_in_exiting_child)
{
	pthread_mutex_t *mutex = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	TEST_SUCC(mutex == MAP_FAILED ? -1 : 0);

	pthread_mutexattr_t attr;
	TEST_SUCC(pthread_mutexattr_init(&attr));
	TEST_SUCC(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
	TEST_SUCC(pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
	TEST_SUCC(pthread_mutex_init(mutex, &attr));

	pid_t pid = CHECK_WITH(fork(), _ret >= 0);
	if (pid == 0) {
		if (pthread_mutex_lock(mutex) != 0)
			_exit(2);
		// Exit while holding the mutex; the kernel must mark it
		// OWNER_DIED and wake the parent.
		_exit(0);
	}

	int status = 0;
	TEST_SUCC(waitpid(pid, &status, 0) < 0 ? -1 : 0);
	TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret == 0);

	TEST_RES(pthread_mutex_lock(mutex), _ret == EOWNERDEAD);
	TEST_SUCC(pthread_mutex_consistent(mutex));
	TEST_SUCC(pthread_mutex_unlock(mutex));

	TEST_SUCC(pthread_mutex_destroy(mutex));
	TEST_SUCC(munmap(mutex, 4096));
}
END_TEST()

struct robust_entry {
	struct robust_entry *next;
	uint32_t word;
};

struct robust_head {
	struct robust_entry *list;
	long futex_offset;
	struct robust_entry *pending;
};

FN_TEST(robust_cycle_exits_cleanly)
{
	uint8_t *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	TEST_SUCC(shared == MAP_FAILED ? -1 : 0);

	pid_t pid = CHECK_WITH(fork(), _ret >= 0);
	if (pid == 0) {
		struct robust_head *head = (struct robust_head *)shared;
		struct robust_entry *entries =
			(struct robust_entry *)(shared + 64);
		head->futex_offset =
			(long)((char *)&entries[0].word - (char *)&entries[0]);
		head->pending = NULL;
		head->list = &entries[0];
		entries[0].next = &entries[1];
		// A two-entry cycle: the kernel must bound its walk and the
		// exiting thread must not hang.
		entries[1].next = &entries[0];
		entries[0].word = entries[1].word =
			(uint32_t)syscall(SYS_gettid);
		if (syscall(SYS_set_robust_list, head, sizeof(*head)) != 0)
			_exit(2);
		_exit(0);
	}

	int status = 0;
	TEST_SUCC(waitpid(pid, &status, 0) < 0 ? -1 : 0);
	TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret == 0);

	TEST_SUCC(munmap(shared, 4096));
}
END_TEST()
