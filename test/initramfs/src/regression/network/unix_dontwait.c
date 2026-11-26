// SPDX-License-Identifier: MPL-2.0

// Tests for MSG_DONTWAIT on AF_UNIX stream sockets, SOCK_SEQPACKET message
// boundaries, and SCM_RIGHTS delivery across stream message boundaries.

#include "../../common/test.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void *unmapped_page(void)
{
	void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return NULL;
	if (munmap(page, 4096) != 0)
		return NULL;
	return page;
}

static int send_with_fd(int sock, int fd, const char *data, size_t len)
{
	char control[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { (void *)data, len };
	struct msghdr msg = { 0 };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (fd >= 0) {
		memset(control, 0, sizeof(control));
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);
		struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg);
		hdr->cmsg_level = SOL_SOCKET;
		hdr->cmsg_type = SCM_RIGHTS;
		hdr->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(hdr), &fd, sizeof(fd));
	}
	return sendmsg(sock, &msg, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

FN_TEST(dontwait_eagain_on_empty_stream)
{
	int pair[2];
	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, pair));

	char byte = 0;
	errno = 0;
	TEST_RES(recv(pair[0], &byte, 1, MSG_DONTWAIT),
		 _ret < 0 && errno == EAGAIN);

	TEST_SUCC(close(pair[0]));
	TEST_SUCC(close(pair[1]));
}
END_TEST()

FN_TEST(seqpacket_large_and_trunc)
{
	int pair[2];
	TEST_SUCC(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));

	// An 8000-byte datagram must pass through intact.
	static char payload[8000];
	static char received[8000];
	memset(payload, 'a', sizeof(payload));
	TEST_SUCC(send(pair[0], payload, sizeof(payload), 0));
	TEST_RES(recv(pair[1], received, sizeof(received), MSG_DONTWAIT),
		 _ret == (ssize_t)sizeof(received) &&
			 memcmp(payload, received, sizeof(payload)) == 0);

	// A short read truncates the datagram and reports MSG_TRUNC; the
	// remainder is discarded, and MSG_TRUNC returns the full length.
	TEST_SUCC(send(pair[0], "first-message", 13, 0));
	char small[5];
	struct iovec iov = { small, sizeof(small) };
	struct msghdr msg = { 0 };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	ssize_t got = TEST_SUCC(recvmsg(pair[1], &msg, MSG_DONTWAIT));
	TEST_RES(got, _ret == 5 && (msg.msg_flags & MSG_TRUNC) &&
			      memcmp(small, "first", 5) == 0);

	TEST_SUCC(send(pair[0], "hello-world", 11, 0));
	char tiny[3];
	struct iovec iov2 = { tiny, sizeof(tiny) };
	struct msghdr msg2 = { 0 };
	msg2.msg_iov = &iov2;
	msg2.msg_iovlen = 1;
	TEST_RES(recvmsg(pair[1], &msg2, MSG_TRUNC | MSG_DONTWAIT),
		 _ret == 11 && (msg2.msg_flags & MSG_TRUNC));

	TEST_SUCC(close(pair[0]));
	TEST_SUCC(close(pair[1]));
}
END_TEST()

FN_TEST(stream_stops_at_rights)
{
	int pair[2];
	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
	int pipe_fds[2];
	TEST_SUCC(pipe(pipe_fds));

	TEST_SUCC(send_with_fd(pair[0], pipe_fds[1], "first", 5));
	TEST_SUCC(send(pair[0], "second", 6, MSG_NOSIGNAL));

	// The first receive must stop at the ancillary data boundary: only the
	// five bytes that carry the file descriptor are delivered.
	char buf[64];
	struct iovec iov = { buf, sizeof(buf) };
	char control[CMSG_SPACE(sizeof(int))];
	struct msghdr msg = { 0 };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	TEST_RES(recvmsg(pair[1], &msg, 0),
		 _ret == 5 && memcmp(buf, "first", 5) == 0);
	int rights = 0;
	for (struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr != NULL;
	     hdr = CMSG_NXTHDR(&msg, hdr)) {
		if (hdr->cmsg_level == SOL_SOCKET &&
		    hdr->cmsg_type == SCM_RIGHTS)
			rights += (int)((hdr->cmsg_len - CMSG_LEN(0)) /
					sizeof(int));
	}
	TEST_RES(rights, _ret == 1);
	for (struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr != NULL;
	     hdr = CMSG_NXTHDR(&msg, hdr)) {
		if (hdr->cmsg_level == SOL_SOCKET &&
		    hdr->cmsg_type == SCM_RIGHTS) {
			int fd;
			memcpy(&fd, CMSG_DATA(hdr), sizeof(fd));
			close(fd);
		}
	}

	// The remaining bytes arrive with a plain non-blocking read.
	char rest[64];
	TEST_RES(recv(pair[1], rest, sizeof(rest), MSG_DONTWAIT),
		 _ret == 6 && memcmp(rest, "second", 6) == 0);

	TEST_SUCC(close(pipe_fds[0]));
	TEST_SUCC(close(pipe_fds[1]));
	TEST_SUCC(close(pair[0]));
	TEST_SUCC(close(pair[1]));
}
END_TEST()

FN_TEST(bad_control_after_bytes_drops_rights)
{
	int pair[2];
	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
	int nullfd = TEST_SUCC(open("/dev/null", O_RDONLY));

	TEST_SUCC(send_with_fd(pair[0], -1, "A", 1));
	TEST_SUCC(send_with_fd(pair[0], nullfd, "B", 1));

	// With an undeliverable control buffer, both payload bytes are still
	// delivered, MSG_CTRUNC is reported, and no file is installed.
	void *bad = unmapped_page();
	TEST_RES(bad == NULL ? -1 : 0, _ret == 0);
	char buf[8];
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg = { 0 };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = bad;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));
	TEST_RES(recvmsg(pair[1], &msg, MSG_DONTWAIT),
		 _ret == 2 && buf[0] == 'A' && buf[1] == 'B' &&
			 (msg.msg_flags & MSG_CTRUNC));

	TEST_SUCC(close(nullfd));
	TEST_SUCC(close(pair[0]));
	TEST_SUCC(close(pair[1]));
}
END_TEST()

FN_TEST(bad_control_single_does_not_hang_stream)
{
	int pair[2];
	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
	int nullfd = TEST_SUCC(open("/dev/null", O_RDONLY));

	TEST_SUCC(send_with_fd(pair[0], nullfd, "Q", 1));

	void *bad = unmapped_page();
	TEST_RES(bad == NULL ? -1 : 0, _ret == 0);
	char buf[8];
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg = { 0 };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = bad;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));
	TEST_RES(recvmsg(pair[1], &msg, MSG_DONTWAIT),
		 _ret == 1 && buf[0] == 'Q' && (msg.msg_flags & MSG_CTRUNC));

	// The message was consumed, so a non-blocking read now reports EAGAIN.
	errno = 0;
	TEST_RES(recv(pair[1], buf, sizeof(buf), MSG_DONTWAIT),
		 _ret < 0 && errno == EAGAIN);

	TEST_SUCC(close(nullfd));
	TEST_SUCC(close(pair[0]));
	TEST_SUCC(close(pair[1]));
}
END_TEST()
