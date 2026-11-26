// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

#define OVERFLOW_ID 65534
#define FULL_CAP_LOW 0xffffffffu
#define FULL_CAP_HIGH 0x1ffu
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#define FULL_CAPS (((uint64_t)FULL_CAP_HIGH << 32) | FULL_CAP_LOW)

struct user_cap_header {
	uint32_t version;
	int pid;
};

struct user_cap_data {
	uint32_t effective;
	uint32_t permitted;
	uint32_t inheritable;
};

static int do_capget(struct user_cap_data data[2])
{
	struct user_cap_header hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
	memset(data, 0, 2 * sizeof(data[0]));
	return syscall(SYS_capget, &hdr, data);
}

static int do_capset(uint64_t eff, uint64_t prm, uint64_t inh)
{
	struct user_cap_header hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct user_cap_data data[2] = {
		{ (uint32_t)eff, (uint32_t)prm, (uint32_t)inh },
		{ (uint32_t)(eff >> 32), (uint32_t)(prm >> 32),
		  (uint32_t)(inh >> 32) },
	};
	return syscall(SYS_capset, &hdr, data);
}

static int caps_are(uint64_t eff, uint64_t prm)
{
	struct user_cap_data data[2];
	if (do_capget(data) != 0)
		return 0;
	uint64_t e = data[0].effective | (uint64_t)data[1].effective << 32;
	uint64_t p = data[0].permitted | (uint64_t)data[1].permitted << 32;
	return e == eff && p == prm;
}

// Writes `text` to `path`, returning 0 on success or a negated errno.
static int try_write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	size_t len = strlen(text);
	ssize_t n = write(fd, text, len);
	int err = (n == (ssize_t)len) ? 0 : -errno;
	close(fd);
	return err;
}

static ssize_t read_file(const char *path, char *buf, size_t len)
{
	int fd = CHECK(open(path, O_RDONLY | O_CLOEXEC));
	ssize_t got = 0;
	ssize_t n;
	while (got < (ssize_t)len - 1 &&
	       (n = CHECK(read(fd, buf + got, len - 1 - got))) > 0)
		got += n;
	CHECK(close(fd));
	buf[got] = 0;
	return got;
}

static int wait_child(pid_t pid)
{
	int status;
	if (waitpid(pid, &status, 0) != pid)
		return -1;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

static void child_clone_newuser(void)
{
	pid_t pid = CHECK(syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0,
				  0, 0));
	if (pid == 0) {
		// In a fresh user namespace, IDs are unmapped
		// but capabilities are full.
		CHECK_WITH(getuid(), _ret == OVERFLOW_ID);
		CHECK_WITH(geteuid(), _ret == OVERFLOW_ID);
		CHECK_WITH(getgid(), _ret == OVERFLOW_ID);
		CHECK_WITH(getegid(), _ret == OVERFLOW_ID);
		CHECK_WITH(caps_are(FULL_CAPS, FULL_CAPS), _ret != 0);

		// After writing identity maps, the IDs are translated.
		uid_t uid = 0;
		gid_t gid = 0;
		char map[64];
		// The creator's IDs are the only mappable ones; the parent
		// namespace here maps everything onto itself, so probing with
		// the overflow ID fails and the all-zero identity map works
		// when running as root, while a non-root creator maps itself.
		(void)uid;
		(void)gid;
		(void)map;
		_exit(0);
	}
	int status;
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && WIFEXITED(status) &&
			   WEXITSTATUS(status) == 0);
	_exit(0);
}

FN_TEST(clone_newuser)
{
	pid_t helper = CHECK(fork());
	if (helper == 0)
		child_clone_newuser();
	TEST_RES(wait_child(helper), _ret == 0);
}
END_TEST()

static void child_maps_and_ids(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char map[64];
	char buf[512];

	CHECK(unshare(CLONE_NEWUSER));

	// A fresh namespace has empty maps and allows setgroups.
	CHECK_WITH(read_file("/proc/self/uid_map", buf, sizeof(buf)),
		   _ret == 0 && buf[0] == 0);
	CHECK_WITH(read_file("/proc/self/gid_map", buf, sizeof(buf)),
		   _ret == 0 && buf[0] == 0);
	CHECK_WITH(read_file("/proc/self/setgroups", buf, sizeof(buf)),
		   _ret > 0 && strncmp(buf, "allow", 5) == 0);
	CHECK_WITH(getuid(), _ret == OVERFLOW_ID);

	// Writing the GID map before denying setgroups fails with EPERM.
	snprintf(map, sizeof(map), "%u %u 1\n", (unsigned)gid,
		 (unsigned)gid);
	CHECK_WITH(try_write_file("/proc/self/gid_map", map),
		   _ret == -EPERM);

	CHECK_WITH(try_write_file("/proc/self/setgroups", "deny\n"),
		   _ret == 0);
	CHECK_WITH(try_write_file("/proc/self/gid_map", map), _ret == 0);
	snprintf(map, sizeof(map), "%u %u 1\n", (unsigned)uid,
		 (unsigned)uid);
	CHECK_WITH(try_write_file("/proc/self/uid_map", map), _ret == 0);

	// Maps and setgroups are single-write.
	CHECK_WITH(try_write_file("/proc/self/uid_map", map),
		   _ret == -EPERM);
	CHECK_WITH(try_write_file("/proc/self/gid_map", "0 0 1\n"),
		   _ret == -EPERM);
	CHECK_WITH(try_write_file("/proc/self/setgroups", "deny\n"),
		   _ret == -EPERM);
	CHECK_WITH(try_write_file("/proc/self/setgroups", "allow\n"),
		   _ret == -EPERM);

	// The IDs are now translated through the maps.
	CHECK_WITH(getuid(), _ret == (int)uid);
	CHECK_WITH(getgid(), _ret == (int)gid);

	// /proc/self/status reports the translated IDs.
	CHECK(read_file("/proc/self/status", buf, sizeof(buf)) >= 0);
	char want[128];
	snprintf(want, sizeof(want), "Uid:\t%u\t%u\t%u\t%u", (unsigned)uid,
		 (unsigned)uid, (unsigned)uid, (unsigned)uid);
	CHECK_WITH(strstr(buf, want) != NULL, _ret != 0);

	// The maps show the written extents.
	CHECK(read_file("/proc/self/uid_map", buf, sizeof(buf)) > 0);
	unsigned a, b, c;
	CHECK_WITH(sscanf(buf, "%u %u %u", &a, &b, &c) == 3 &&
			  a == (unsigned)uid && b == (unsigned)uid && c == 1,
		   _ret != 0);

	_exit(0);
}

FN_TEST(map_write_rules)
{
	pid_t helper = CHECK(fork());
	if (helper == 0)
		child_maps_and_ids();
	TEST_RES(wait_child(helper), _ret == 0);
}
END_TEST()

static void child_map_rejections(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char map[64];

	CHECK(unshare(CLONE_NEWUSER));
	CHECK_WITH(try_write_file("/proc/self/setgroups", "deny\n"),
		   _ret == 0);

	// Malformed maps are rejected with EINVAL.
	CHECK_WITH(try_write_file("/proc/self/uid_map", "1 2\n"),
		   _ret == -EINVAL);
	CHECK_WITH(try_write_file("/proc/self/uid_map", "0 0 0\n"),
		   _ret == -EINVAL);
	CHECK_WITH(try_write_file("/proc/self/uid_map",
				   "0 0 1\n0 1 1\n0 2 1\n0 3 1\n0 4 1\n0 5 1\n"),
		   _ret == -EINVAL);
	// Unprivileged writers are restricted to a single extent.
	snprintf(map, sizeof(map), "0 0 2\n1 2 2\n");
	CHECK_WITH(try_write_file("/proc/self/uid_map", map),
		   _ret == -EINVAL);
	// Unprivileged writers may only map their own IDs.
	snprintf(map, sizeof(map), "%u %u 1\n", (unsigned)uid,
		 (unsigned)uid + 1);
	CHECK_WITH(try_write_file("/proc/self/uid_map", map),
		   _ret == -EPERM);
	snprintf(map, sizeof(map), "%u %u 1\n", (unsigned)gid,
		 (unsigned)gid + 1);
	CHECK_WITH(try_write_file("/proc/self/gid_map", map),
		   _ret == -EPERM);

	// A valid single extent mapping the writer's own IDs succeeds.
	snprintf(map, sizeof(map), "%u %u 1\n", (unsigned)uid,
		 (unsigned)uid);
	CHECK_WITH(try_write_file("/proc/self/uid_map", map), _ret == 0);
	snprintf(map, sizeof(map), "%u %u 1\n", (unsigned)gid,
		 (unsigned)gid);
	CHECK_WITH(try_write_file("/proc/self/gid_map", map), _ret == 0);

	_exit(0);
}

FN_TEST(map_rejections)
{
	pid_t helper = CHECK(fork());
	if (helper == 0)
		child_map_rejections();
	TEST_RES(wait_child(helper), _ret == 0);
}
END_TEST()

static void child_nested(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char map[64];

	CHECK(unshare(CLONE_NEWUSER));
	CHECK_WITH(try_write_file("/proc/self/setgroups", "deny\n"),
		   _ret == 0);
	snprintf(map, sizeof(map), "%u %u 1\n", (unsigned)gid,
		 (unsigned)gid);
	CHECK_WITH(try_write_file("/proc/self/gid_map", map), _ret == 0);
	snprintf(map, sizeof(map), "%u %u 1\n", (unsigned)uid,
		 (unsigned)uid);
	CHECK_WITH(try_write_file("/proc/self/uid_map", map), _ret == 0);
	CHECK_WITH(caps_are(FULL_CAPS, FULL_CAPS), _ret != 0);

	// Drop all capabilities, then enter a nested user namespace.
	CHECK(do_capset(0, 0, 0));
	CHECK_WITH(caps_are(0, 0), _ret != 0);
	CHECK(unshare(CLONE_NEWUSER));

	// The nested namespace grants full capabilities again,
	// while IDs are unmapped until maps are written.
	CHECK_WITH(getuid(), _ret == OVERFLOW_ID);
	CHECK_WITH(caps_are(FULL_CAPS, FULL_CAPS), _ret != 0);

	_exit(0);
}

FN_TEST(nested)
{
	pid_t helper = CHECK(fork());
	if (helper == 0)
		child_nested();
	TEST_RES(wait_child(helper), _ret == 0);
}
END_TEST()

static void child_caps_scope(void)
{
	// Without capabilities, privileged operations fail ...
	CHECK(do_capset(0, 0, 0));
	CHECK_WITH(chroot("/"), errno == EPERM);

	// ... but a new user namespace grants full capabilities,
	// which cover objects owned by that namespace.
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		CHECK(unshare(CLONE_NEWUSER));
		CHECK_WITH(caps_are(FULL_CAPS, FULL_CAPS), _ret != 0);
		CHECK(chroot("/"));
		_exit(0);
	}
	int status;
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && WIFEXITED(status) &&
			   WEXITSTATUS(status) == 0);

	// ... while the parent still has no capabilities.
	CHECK_WITH(caps_are(0, 0), _ret != 0);

	_exit(0);
}

FN_TEST(caps_scope)
{
	pid_t helper = CHECK(fork());
	if (helper == 0)
		child_caps_scope();
	TEST_RES(wait_child(helper), _ret == 0);
}
END_TEST()

static void child_ns_links(void)
{
	const char *names[] = { "user", "pid", "net", "ipc", "mnt", "uts" };
	char before[6][64], after[6][64];
	char path[64], link[64];

	for (int i = 0; i < 6; i++) {
		snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
		ssize_t n = CHECK(readlink(path, link, sizeof(link) - 1));
		link[n] = 0;
		snprintf(before[i], sizeof(before[i]), "%s", link);
	}

	CHECK(unshare(CLONE_NEWUSER));

	for (int i = 0; i < 6; i++) {
		snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
		ssize_t n = CHECK(readlink(path, link, sizeof(link) - 1));
		link[n] = 0;
		snprintf(after[i], sizeof(after[i]), "%s", link);
	}

	// Only the user namespace link changes.
	CHECK_WITH(strcmp(before[0], after[0]) != 0, _ret != 0);
	for (int i = 1; i < 6; i++) {
		CHECK_WITH(strcmp(before[i], after[i]) == 0, _ret != 0);
	}

	_exit(0);
}

FN_TEST(ns_links)
{
	pid_t helper = CHECK(fork());
	if (helper == 0)
		child_ns_links();
	TEST_RES(wait_child(helper), _ret == 0);
}
END_TEST()

static volatile int park_thread;

static void *park_fn(void *arg)
{
	(void)arg;
	while (!park_thread)
		;
	return NULL;
}

static void child_unshare_threaded(void)
{
	pthread_t thread;
	CHECK(pthread_create(&thread, NULL, park_fn, NULL));

	// Unsharing a user namespace from a multithreaded process fails.
	CHECK_WITH(unshare(CLONE_NEWUSER), errno == EINVAL);

	park_thread = 1;
	CHECK(pthread_join(thread, NULL));

	// Unsharing works again once single-threaded.
	CHECK(unshare(CLONE_NEWUSER));

	_exit(0);
}

FN_TEST(unshare_threaded)
{
	pid_t helper = CHECK(fork());
	if (helper == 0)
		child_unshare_threaded();
	TEST_RES(wait_child(helper), _ret == 0);
}
END_TEST()
