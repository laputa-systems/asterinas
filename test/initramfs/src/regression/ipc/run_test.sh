#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

./futex/futex_requeue
./futex/futex_cmp_requeue
./futex/robust_futex

./pipe/pipe_err
./pipe/process_pipe_available
./pipe/short_rw
./pipe/close_wakeup

./sem/sem

./shm/posix_shm
