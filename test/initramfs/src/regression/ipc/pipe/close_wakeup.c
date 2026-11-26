// SPDX-License-Identifier: MPL-2.0

// Tests that closing a pipe wakes a blocked reader with EOF, even when the
// close happens from another thread while the read is in progress.

#include "../../common/test.h"

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

static int fds[2];
static atomic_int started;
static atomic_int read_result;

static void *blocked_reader(void *arg)
{
	(void)arg;
	char c;
	atomic_store(&started, 1);
	ssize_t n = read(fds[0], &c, 1);
	atomic_store(&read_result, (int)n);
	return NULL;
}

FN_TEST(close_wakes_blocked_reader)
{
	for (int i = 0; i < 50; ++i) {
		pthread_t reader;
		atomic_store(&started, 0);
		atomic_store(&read_result, -99);

		TEST_SUCC(pipe(fds));
		TEST_SUCC(pthread_create(&reader, NULL, blocked_reader, NULL));
		while (!atomic_load(&started))
			usleep(100);
		// Let the reader block, then close both ends like Chromium's
		// `close_race` fixture does.
		usleep(1000);
		TEST_SUCC(close(fds[0]));
		TEST_SUCC(close(fds[1]));
		TEST_SUCC(pthread_join(reader, NULL));

		// The reader must observe EOF, not an error or a hang.
		TEST_RES(atomic_load(&read_result), _ret == 0);
	}
}
END_TEST()
