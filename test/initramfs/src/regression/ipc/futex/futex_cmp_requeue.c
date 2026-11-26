// SPDX-License-Identifier: MPL-2.0

// Tests for FUTEX_CMP_REQUEUE (private) and FUTEX_CLOCK_REALTIME validation.

#include "../../common/test.h"

#include <linux/futex.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_CMP_REQUEUE_PRIVATE
#define FUTEX_CMP_REQUEUE_PRIVATE 132
#endif

static long futex(uint32_t *uaddr, int op, uint32_t val, unsigned long val2,
		  uint32_t *uaddr2, uint32_t val3)
{
	return syscall(SYS_futex, uaddr, op, val, val2, uaddr2, val3);
}

static uint32_t futex_a;
static uint32_t futex_b;

static void *wait_on_a(void *arg)
{
	(void)arg;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += 5;
	futex(&futex_a, FUTEX_WAIT_PRIVATE, 0, (unsigned long)&ts, NULL, 0);
	return NULL;
}

FN_TEST(cmp_requeue_moves_waiter_without_waking)
{
	pthread_t thread;
	futex_a = 0;
	futex_b = 0;

	TEST_SUCC(pthread_create(&thread, NULL, wait_on_a, NULL));

	// Wait until the waiter has blocked, then requeue it without waking.
	long moved = -1;
	for (int i = 0; i < 100 && moved == -1; ++i) {
		long ret = futex(&futex_a, FUTEX_CMP_REQUEUE_PRIVATE, 0, 1,
				  &futex_b, 0);
		if (ret == 1)
			moved = ret;
		else
			usleep(10 * 1000);
	}
	TEST_RES(moved, _ret == 1);

	// The waiter now sleeps on `futex_b`: waking `futex_a` must wake nobody.
	TEST_RES(futex(&futex_a, FUTEX_WAKE_PRIVATE, 1, 0, NULL, 0),
		 _ret == 0);
	TEST_RES(futex(&futex_b, FUTEX_WAKE_PRIVATE, 1, 0, NULL, 0),
		 _ret == 1);

	TEST_SUCC(pthread_join(thread, NULL));
}
END_TEST()

FN_TEST(cmp_requeue_checks_expected_value)
{
	pthread_t thread;
	futex_a = 0;
	futex_b = 0;

	TEST_SUCC(pthread_create(&thread, NULL, wait_on_a, NULL));
	usleep(100 * 1000);

	// The futex word holds 0, so expecting 7 must fail with EAGAIN and
	// leave the waiter in place.
	TEST_ERRNO(futex(&futex_a, FUTEX_CMP_REQUEUE_PRIVATE, 0, 1, &futex_b,
			 7),
		   EAGAIN);
	TEST_RES(futex(&futex_b, FUTEX_WAKE_PRIVATE, 1, 0, NULL, 0),
		 _ret == 0);

	// Now requeue for real and wake the waiter on its new address.
	TEST_RES(futex(&futex_a, FUTEX_CMP_REQUEUE_PRIVATE, 0, 1, &futex_b,
		       0),
		 _ret == 1);
	TEST_RES(futex(&futex_b, FUTEX_WAKE_PRIVATE, 1, 0, NULL, 0),
		 _ret == 1);

	TEST_SUCC(pthread_join(thread, NULL));
}
END_TEST()

FN_TEST(cmp_requeue_rejects_negative_counts)
{
	TEST_ERRNO(futex(&futex_a, FUTEX_CMP_REQUEUE_PRIVATE, (uint32_t)-1, 0,
			 &futex_b, 0),
		   EINVAL);
	TEST_ERRNO(futex(&futex_a, FUTEX_CMP_REQUEUE_PRIVATE, 0,
			 (unsigned long)-1, &futex_b, 0),
		   EINVAL);
}
END_TEST()

FN_TEST(clock_realtime_only_with_wait_bitset)
{
	uint32_t word = 0;
	struct timespec past;
	clock_gettime(CLOCK_REALTIME, &past);
	past.tv_sec -= 1;

	// A `FUTEX_WAIT_BITSET` with a past `CLOCK_REALTIME` deadline times out.
	TEST_ERRNO(futex(&word, FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME, 0,
			 (unsigned long)&past, NULL, 0xffffffff),
		   ETIMEDOUT);

	// `FUTEX_WAIT` and `FUTEX_WAKE` must reject `FUTEX_CLOCK_REALTIME`.
	struct timespec rel = { 0, 1000000 };
	TEST_ERRNO(futex(&word,
			 FUTEX_WAIT | FUTEX_CLOCK_REALTIME | FUTEX_PRIVATE_FLAG,
			 0, (unsigned long)&rel, NULL, 0),
		   ENOSYS);
	TEST_ERRNO(futex(&word,
			 FUTEX_WAKE | FUTEX_CLOCK_REALTIME | FUTEX_PRIVATE_FLAG,
			 1, 0, NULL, 0),
		   ENOSYS);
}
END_TEST()
