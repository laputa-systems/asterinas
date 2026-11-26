// SPDX-License-Identifier: MPL-2.0

// Tests that a nested epoll file stops reporting readable once the inner
// epoll's events have been drained.

#include "../../common/test.h"
#include <sys/epoll.h>
#include <unistd.h>

FN_TEST(nested_epoll_drain)
{
	int outer = TEST_SUCC(epoll_create1(0));
	int inner = TEST_SUCC(epoll_create1(0));
	int fds[2];
	TEST_SUCC(pipe(fds));

	struct epoll_event ev = { .events = EPOLLIN, .data.fd = fds[0] };
	TEST_SUCC(epoll_ctl(inner, EPOLL_CTL_ADD, fds[0], &ev));
	ev.data.fd = inner;
	TEST_SUCC(epoll_ctl(outer, EPOLL_CTL_ADD, inner, &ev));

	struct epoll_event out;
	char c;

	// Idle: nothing is ready.
	TEST_RES(epoll_wait(outer, &out, 1, 0), _ret == 0);

	// A write makes the inner epoll (and hence the outer one) readable.
	TEST_SUCC(write(fds[1], "x", 1));
	TEST_RES(epoll_wait(outer, &out, 1, 1000),
		 _ret == 1 && out.data.fd == inner);

	// Draining the pipe must drain the nested readiness as well.
	TEST_SUCC(read(fds[0], &c, 1));
	TEST_RES(epoll_wait(outer, &out, 1, 0), _ret == 0);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
	TEST_SUCC(close(inner));
	TEST_SUCC(close(outer));
}
END_TEST()
