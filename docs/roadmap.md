# Roadmap

This is the single plan for this repository: all current and future work, and the handoff for resuming it. Campaigns are sections below, and their items interleave in **Sequence**. "Resume the roadmap" means continue from **Status**.

## Status

- **State:** active. LC-01, LC-03, and LC-04 are accepted. LC-02 is integrated but its acceptance is suspended while reviewer-found correctness defects are repaired; LC-05 waits on that repair.
- **Campaign:** [Linux compatibility and reliability](#linux-compatibility-and-reliability) (`LC`).
- **Last accepted revision:** `c98ac38d8` for LC-04; `2580c8dae` for LC-03; `e58cc4bdb` for LC-01. The regression initramfs build, host unit tests, lint, and PVH build are green. The full regression boot reaches userspace and runs the suite; its remaining recorded red case is corrupted generated NVMe input, not a kernel panic (see [Baseline](#baseline)).
- **Red or parked:** `setup_mount_nvme_ext2` is red because `test/initramfs/build/nvme0n1.img` has a bad ext2 superblock. Preserve the image as evidence until a later storage lane root-causes or deliberately regenerates it. `make ktest` was red at `798fb7b12` only for `realtime_clocks_store_fractional_seconds`; `914a9c245` fixes that test and its focused ktest is green. LC-02 repair is red: independent review found a fail-open exec gate and cleanup gap, non-hermetic errno comparison, incomplete strict validation, incomplete accounting contradictions, and evidence-capture failures misclassified as clean exits.
- **Next slice:** repair LC-02, then LC-05.
- **First command:** `python3 test/qualification/run.py selftest && python3 test/qualification/run.py inventory --check`

## Charter

- Decide and keep going. Record a decision only when a later slice depends on it, by editing **Decisions** in place.
- Within the execution grant in [Execution boundary](#execution-boundary-and-non-goals), proceed without waiting for approval. This roadmap does not provide missing permission. Park an item that needs authority outside the grant.
- Hard stops are few, and each one parks the item: an irreversible or outside-the-repo action, a boundary this roadmap forbids, or a loop that cannot check anything. Pushing is always forbidden.
- Fix egregious problems met on the way, in their own commit, to these thresholds: a panic, hang, or memory-safety fault reachable from an unprivileged guest program; a syscall in code you touch that reports success for an effect it does not perform (security, resource, lifecycle, or durability); a single existing test whose run exceeds 10x its Linux-reference time and 60 s under the same backend; a host harness command that takes over 2 s before its first guest boot. Record anything else as a one-line **Later** entry and leave it.
- Parity before optimization. Product-performance numbers are measured and logged, never gating, until the PF items.
- Parallel lanes for the disjoint sets named in **Sequence**, serial otherwise, each in a worktree at `.work/wt/<lane>`, never `/tmp`, following the `orchestrate` skill's worktree lifecycle. Run the `orchestrate` parent steering checkpoint after each accepted slice, on resume, and when a slice fails twice.
- Every commit is a Conventional Commit with the workstream as its scope (`qual`, `storage`, `ext4`, `process`, `vfs`, `mm`, `cgroup`, `net`, `security`, `device`, `arch`, `perf`). The item ID belongs in the body. Code comments never cite the roadmap.
- A failing item gets its cause established (`root-cause`) before any retry. Three attempts per slice, then park it on its branch with the cause and a retry condition in **Status**. A shared environment blocker has one owner: the parent.
- Slices that change storage transaction logic, permission boundaries, shared lifetime or locking, or harness expectations (selectors, normalizers, validators, deadlines, dispositions) get an independent `review` lane before integration.
- Never improve a result by deleting tests, accepting empty runs, weakening assertions, broadening allowed outcomes, raising deadlines after a failure, disabling application security, changing oracle settings, or moving a case out of a selection. Setup failures are fixed as setup; kernel failures in the kernel.

## Sequence

An item is accepted when its acceptance command exits 0 on the integrated tree, the narrowest affected suite is green, and (for kernel changes) `make test` and the PVH build stay green. Milestone runs (G0–G6) also rerun every previously qualified profile.

`run.py` is `python3 test/qualification/run.py`, created in LC-02. `D` is the dev-container prefix `docker run --rm --privileged -v "$PWD":/root/asterinas -w /root/asterinas asterinas/dev:0.19.0-20261012`.

**Ownership sets.** Items in different sets run in parallel by default; items in the same set run serially in the order listed. Shared files have one writer, the integrating parent, who applies other items' edits to them at integration: `Cargo.toml`, `Cargo.lock`, every `Cargo.toml` `[dependencies]` block, `kernel/core/src/syscall/arch/*.rs`, `kernel/core/src/syscall/mod.rs`, `kernel/core/src/fs/fs_impls/mod.rs`, `test/initramfs/nix/default.nix`, `test/initramfs/src/regression/Makefile`, `test/qualification/profiles/**`, `test/qualification/inputs.lock.json`.

| Set | Owns |
| --- | --- |
| `Q` harness | `test/qualification/` except `contracts/<area>/`, `fixtures/<area>/`, `linux/`, `inventory/`; `test/initramfs/nix/qualification.nix`; `tools/firecracker_args.sh` |
| `L` reference | `test/qualification/linux/` |
| `I` inventory | `test/qualification/inventory/` |
| `BLK` block | `kernel/core/comps/block/`, `kernel/core/comps/virtio/src/device/block/` |
| `PC` page cache | `kernel/core/src/vm/page_cache/`, `kernel/core/src/fs/vfs/`, `kernel/core/src/syscall/{fsync,sync*,msync}.rs`, `kernel/core/src/fs/fs_impls/ext2/` |
| `X4` ext4 | `kernel/libs/aster-ext4-format/`, `kernel/core/src/fs/fs_impls/ext4/`, `test/qualification/{contracts,fixtures}/ext4/` |
| `PR` process | `kernel/core/src/process/` (except `namespace/`, `credentials/`), `kernel/core/src/syscall/` process, futex, signal, epoll, poll, eventfd, timerfd, signalfd, pipe files, `kernel/core/src/fs/pipe/` |
| `MM` memory | `kernel/core/src/vm/` except `page_cache/`, `kernel/core/src/syscall/{mmap,munmap,mprotect,mremap,madvise,memfd_create}.rs` and new mapping syscalls |
| `VF` vfs ABI | `kernel/core/src/fs/{file,utils}/`, `kernel/core/src/fs/fs_impls/{tmpfs,ramfs,overlayfs}/`, `kernel/core/src/syscall/` path, mount, lock, inotify, stat files |
| `CG` cgroup/sched | `kernel/core/src/fs/fs_impls/cgroupfs/`, `kernel/core/src/sched/` |
| `NET` network | `kernel/core/src/net/`, `kernel/core/comps/network/`, `kernel/libs/aster-bigtcp/`, `kernel/core/src/syscall/` socket files |
| `TM` time and devices | `kernel/core/src/time/`, `kernel/core/comps/time/`, `kernel/core/src/vdso.rs`, `kernel/core/src/device/{mem,misc}/` |
| `SEC` security | `kernel/core/src/security/`, `kernel/core/src/process/{credentials,namespace}/`, new `landlock_*` and `seccomp` syscall files |
| `DEV` devices | `kernel/core/src/device/{evdev,pty,tty,model.rs,registry}/`, `kernel/core/comps/{input,framebuffer,device}/`, `kernel/comps/`, `kernel/core/src/fs/fs_impls/{sysfs,devtmpfs,procfs}/` |
| `ARCH` aarch64 | `ostd/src/arch/arm/`, `kernel/core/src/arch/arm*`, aarch64 boot glue |

Each kernel item also owns `test/qualification/contracts/<area>/` and `test/initramfs/src/regression/<area>/` for its area.

**Phase 0, ground**

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-01 | Green the loop: fix every regression-initramfs build error, then time `make ktest`, `make lint`, and one full regression run and record them and the red regression cases in **Baseline** | `Q` + `test/initramfs/src/regression/` sources that fail to build | — | `D make initramfs ENABLE_REGRESSION_TEST=true` exits 0; then `D make run_kernel AUTO_TEST=regression ENABLE_KVM=0` runs to completion (pass or a recorded red list). Existing make targets boot QEMU TCG inside the container; only `run.py` boots on the host. |

**Phase 1, harness (G0, G1)**

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-02 | Runner core: case manifest, run-bound result protocol, dispositions, accounting, supervisor, evidence bundle | `Q` | LC-01 | `run.py selftest` exits 0 with every H1 control in [Qualification rules](#qualification-rules) detected |
| LC-03 | Reference Linux v6.18.y built from source with a checked-in config | `L` | LC-01 | `D make -C test/qualification/linux` produces `bzImage` whose hash matches the committed expected hash on a second clean build |
| LC-04 | Inventory: dispatch entries, SCML, stubs, unsupported-success paths, blocklists, `__asterinas__` branches | `I` | LC-01 | `run.py inventory --check` regenerates the inventory and every dispatch entry and blocklisted case has a status and source |
| LC-05 | Input lock, host QEMU adapter, probe payload, Linux-to-Linux self-comparison | `Q` | LC-02, LC-03, LC-04 | `run.py lock --verify && run.py run --profile selfcheck --candidate linux && run.py run --profile selfcheck --controls` → **G0** |
| LC-06 | Disk and network adapter: generated scratch disks with serial identity, `cache=writeback`, `blkdebug`, `blklogwrites`, isolated network, verified teardown | `Q` | LC-05 | `run.py run --profile adapter --controls` (wrong disk, failed mount, missing device, guest hang, orphaned VM all detected) |
| LC-07 | Ext2 pilot corpus; capture the paired failing baseline | `Q`, `contracts/ext2/` | LC-06 | `run.py run --profile pilot-ext2 --baseline` completes with every case holding a terminal disposition and zero `HARNESS_ERROR` |
| LC-08 | FD/readiness pilot: eventfd, epoll, pipe and FD lifetime | `contracts/fd/` | LC-05 | `run.py run --profile pilot-fd` all required PASS, and `--controls` detects a deliberate readiness defect |
| LC-09 | Retain asynchronous writeback errors; per-open-file error observation in fsync/fdatasync/msync/syncfs | `PC` | LC-07 | `run.py run --profile s0-errors` (blkdebug EIO on writeback, two descriptors, repeated errors) |
| LC-10 | Block requests: split oversize BIOs, backpressure, partial I/O, failed flush, `queue/write_cache` sysfs on both kernels | `BLK` | LC-07 | `run.py run --profile s0-block` |
| LC-11 | Persistence model: traceable durable/volatile memory disk, crash-cut enumeration from `blklogwrites` logs, omitted-sync control | `Q`, `fixtures/storage/`, `kernel/core/src/fs/fs_impls/ext2/test_utils.rs` | LC-06 | `make test` green for the model's checks, and `run.py run --profile s0-persistence --controls` detects the omitted sync |
| LC-12 | Fix the ext2 pilot failures from LC-07 | `PC` | LC-09, LC-11 | `run.py run --profile pilot-ext2` all required PASS on both kernels with `e2fsck -fn` clean → **G1** with LC-08–LC-11 |
| LC-13 | Corpus integration: native-report parsers for gtest, TAP/KTAP, Kirk JSON, xfstests; wrapper audit; regression registry and compatibility report generation | `Q` | LC-07, LC-08 | `run.py run --profile corpus-smoke --controls` (empty gtest filter, zero-execution run, all-skip, missing subtest detected for each suite) |

**Phase 2, parity: ext4 (G2).** The `X4` track has priority; other tracks use remaining lane headroom.

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-14 | `ext4-ordered-v1` fixtures: pinned e2fsprogs, explicit mkfs recipe, inspected feature masks, multi-group, nearly-full, fragmented, sparse, large-address and malformed images | `X4` fixtures | LC-05 | `run.py fixtures --build ext4 --check` reproduces every fixture hash and feature mask |
| LC-15 | Ext4 format crate: superblock, group descriptors, feature policy, checksums; registration that refuses unsupported and recovery-needed images | `X4` | LC-12, LC-14 | `make test` (crate) and `run.py run --profile ext4-policy` |
| LC-16 | Clean read-only reader: inodes, extents, holes, unwritten extents, linear and HTree directories, xattrs, ACLs, symlinks; bounded work on corrupt input | `X4` | LC-15 | `run.py run --profile ext4-read` and `make test` property tests over malformed fixtures |
| LC-17 | JBD2 recovery state machine in the format crate | `X4` | LC-15 | `make test` (crate): wrap, revoke, escape, truncated and corrupt records, repeated replay |
| LC-18 | JBD2 recovery at mount; crash-image clone workflow; error state never marked clean | `X4` | LC-16, LC-17, LC-11 | `run.py run --profile ext4-recovery` (Linux-produced replay-only fixtures, interrupted recovery, `e2fsck -fn`) |
| LC-19 | Transactions: handles, credits, ordered data, commit, checkpoint, log-space backpressure, abort to read-only | `X4` | LC-18, LC-09, LC-10 | `run.py run --profile ext4-journal --features ext4_rw_experimental` |
| LC-20 | Allocation, inode create/delete, extent insert/split/merge/grow/collapse, unwritten conversion, truncate and extend zeroing | `X4` | LC-19 | `run.py run --profile ext4-alloc --features ext4_rw_experimental` |
| LC-21 | Directories: create, HTree growth, hash collisions, links, rename, renameat2 flags | `X4` | LC-20 | `run.py run --profile ext4-dir --features ext4_rw_experimental` |
| LC-22 | Orphans: open-unlink, interrupted truncate/extend, recovery-side cleanup, transactional orphan-chain updates | `X4` | LC-21 | `run.py run --profile ext4-orphan --features ext4_rw_experimental` |
| LC-23 | Xattrs, ACLs, file capabilities, ENOSPC at data and metadata boundaries, short writes, copy faults, mmap and direct-I/O coherency; remove `ext4_rw_experimental` and enable writable mounts | `X4` | LC-22 | `run.py run --profile ext4-ops` (no feature flag) |
| LC-24 | xfstests and pjdfstest on ext4 through the existing template; fixed applicable list with per-case applicability | `X4`, `test/initramfs/src/conformance/{xfstests,pjdfstest}/` | LC-23, LC-13 | `run.py run --profile ext4-suites` |
| LC-25 | Cross-mount and cross-recovery matrix; application durability (SQLite rollback and WAL, atomic publish, rename, open-unlink, concurrent writers, mmap/truncate, full volume); bounded crash campaign | `X4` | LC-24 | `run.py run --profile storage-ext4 --controls` → **G2** |

**Phase 2, parity: services (G3).** May start after G1 in parallel with the `X4` track.

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-26 | Process lifecycle: clone/clone3/fork/vfork/exec/wait, thread-group exit, PID 1 and reparenting, process groups and sessions, pidfds, CLOEXEC, struct-size and flag validation | `PR` | LC-13 | `run.py run --profile c0-lifecycle` |
| LC-27 | Futexes (shared, private, robust, requeue), signals and restart, poll/select/epoll modes, eventfd/signalfd/timerfd, pipes, SCM_RIGHTS; glibc and musl lanes | `PR` | LC-26 | `run.py run --profile c0-sync` plus the pinned multithreaded workloads in `c0-apps` |
| LC-28 | Mappings: anonymous/file/shared/private, COW, mprotect, MAP_FIXED_NOREPLACE, EOF SIGBUS, memfd seals, copy-user faults; `mincore`, bounded `mlock`, `membarrier` | `MM` | LC-27, LC-09 | `run.py run --profile c1-mm` |
| LC-29 | Paths and mounts: openat2, O_PATH, O_TMPFILE, symlinks, bind mounts, statx, getdents, mount namespaces, the existing modern mount API | `VF` | LC-26 | `run.py run --profile c2-vfs` on ext2 (ext4 rerun after LC-23) |
| LC-30 | POSIX, OFD and flock locks under fork/dup/close/exec/interrupt; inotify lifetime, rename pairs, overflow, unlink/unmount | `VF` | LC-29 | `run.py run --profile c2-locks-notify` |
| LC-31 | Clean-page reclaim, bounded dirty writeback and throttling, allocation-failure propagation, non-contiguous pipe and buffer growth | `MM`, `PC` | LC-28, LC-12 | `run.py run --profile m0-reclaim` |
| LC-32 | Explicit OOM policy; leak audit of caches, epoll, sockets, dentries, tasks, pages; responsive supervisor under exhaustion | `MM` | LC-31 | `run.py run --profile m0-oom` |
| LC-33 | TCP and UDP semantics: connect, shutdown, reset, half-close, retransmission, backpressure, buffer limits, truncation, error queues, `recvmmsg` | `NET` | LC-27 | `run.py run --profile n0-inet` |
| LC-34 | Unix stream, datagram, seqpacket; ancillary data, credentials, SCM_RIGHTS lifetime and FD limits | `NET` | LC-33 | `run.py run --profile n0-unix` |
| LC-35 | Endpoint configuration: IPv4/IPv6 addresses, routes, neighbors, dual-stack, IPv6 discovery and lifetimes, MTU, netlink requests, dumps, notifications, acks | `NET` | LC-34 | `run.py run --profile n1-config` |
| LC-36 | Clocks and timers: real/monotonic/boottime, clock adjustment, absolute timers on clock steps, vDSO consistency; console and entropy device lifecycle; QMP pause/resume | `TM` | LC-27 | `run.py run --profile n1-time` |
| LC-37 | Diagnostics: devtmpfs/sysfs/uevent ordering and coldplug, `/proc`, `/sys`, `/dev/kmsg`, supported sysctls; unsupported distinguishable from zero | `DEV` | LC-27 | `run.py run --profile d0-diag` |
| LC-38 | Services scenario: nginx, curl over TLS, dnsmasq, sqlite3, gcc/make build, chrony, tmux supervisor under SMP, bounded memory, churn and disruption | `Q`, `contracts/services/` | LC-25, LC-30, LC-32, LC-35, LC-36, LC-37 | `run.py run --profile services` → **G3** |

**Phase 2, parity: confined services (G4)**

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-39 | CPU weight and quota enforcement and statistics | `CG` | LC-32 | `run.py run --profile m1-cpu` |
| LC-40 | Memory charging (current/high/max/events) with reclaim and OOM, PID limits, single-node cpuset, freezer, kill; migration, rollback, delegation | `CG` | LC-39 | `run.py run --profile m1-mem` |
| LC-41 | Credentials: IDs, groups, capabilities, setuid/setgid, file capabilities, `no_new_privs`, exec transitions, ptrace checks, mount permissions, procfs visibility | `SEC` | LC-27 | `run.py run --profile q0-creds` |
| LC-42 | Landlock ABI 6 | `SEC` | LC-41, LC-34, LC-23 | `run.py run --profile q0-landlock` (kselftest 6.18 Landlock plus adversarial rename/link/mount/FD cases) |
| LC-43 | Seccomp classic BPF: validation, stacking, precedence, TSYNC, inheritance, actions, `SECCOMP_GET_ACTION_AVAIL` | `SEC` | LC-41 | `run.py run --profile q0-seccomp` (kselftest 6.18 `seccomp_bpf`) |
| LC-44 | PID and user namespaces: UID/GID maps, scoped capabilities, nested visibility, namespace-init reaping, signals, pidfds | `SEC` | LC-43, LC-40 | `run.py run --profile q1-ns` |
| LC-45 | Network namespaces: separated network state, address/route/socket visibility, teardown isolation | `SEC`, `NET` | LC-44, LC-35 | `run.py run --profile q1-netns` |
| LC-46 | Confined-services scenario: bubblewrap (user, PID, mount, network namespaces and seccomp) plus Landlock sandboxer over the services workloads | `Q`, `contracts/confined/` | LC-38, LC-42, LC-45 | `run.py run --profile confined-services` → **G4** |

**Phase 2, parity: virtual desktop and audio (G5)**

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-47 | PTY/TTY: sessions, job control, window changes, hangup, canonical/raw, permissions | `DEV` | LC-37, LC-41 | `run.py run --profile d0-tty` |
| LC-48 | Evdev: key/button state, packet boundaries, SYN_DROPPED, nonblocking readiness, grab/revoke, disconnect | `DEV` | LC-47 | `run.py run --profile d0-evdev` (QMP-injected input, pinned libevdev cases) |
| LC-49 | DRM: dumb buffers, mapping, DRM master, FD passing, event read/poll, pageflip completion, teardown, denial; atomic modesetting if weston requires it | `DEV` | LC-48, LC-28 | `run.py run --profile d1-drm` |
| LC-50 | Desktop scenario: weston (pixman, DRM backend) and weston-terminal with QMP input and screendump pixel checks, compositor death and recovery | `Q`, `contracts/desktop/` | LC-49, LC-32 | `run.py run --profile virtual-desktop` → **G5** |
| LC-51 | Virtual audio: virtio-snd, ALSA PCM and control, stream negotiation, buffers, poll/mmap/read/write, timestamps, xruns, device loss | `DEV` | LC-50 | `run.py run --profile virtual-audio` (playback validated from the QEMU `wav` audiodev file) |

**Phase 2, parity: arm64 (G6, portability half)**

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-52 | AArch64: `vm-core` and `storage-ext4` profiles under `qemu-system-aarch64 -accel hvf` against a source-built Linux arm64 reference | `ARCH`, `L` | LC-25 | `run.py run --arch aarch64 --profile storage-ext4` |

**Phase 3, hardening**

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-53 | Inherited-contract rerun: every qualified profile together; fix regressions; contract changes written up in the book's compatibility pages and SCML | all, serial | LC-51, LC-52 | `run.py run --profile all` |

**Phase 4, optimization**

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| PF-1 | Benchmark profiles: boot, syscall/FD, faults/COW, reclaim, wakeups, block throughput and sync latency, metadata, TCP/UDP, idle; validated output; frozen budgets | `Q`, `test/initramfs/src/benchmark/` | LC-53 | `run.py bench --profile perf-core --trials 5` produces a validated report |
| PF-2 | Optimizations from PF-1's top measured bottlenecks, one item per bottleneck | per bottleneck | PF-1 | `run.py bench` before/after per [Decisions](#decisions) P14 and `run.py run --profile all` |

**Phase 5, close**

| ID | Item | Set | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| LC-54 | Close: delete dead paths (superseded wrappers, experimental flags, unused fixtures) with liveness proven by `rg` and a green `run.py run --profile all`; run `ultrareview`; fix P1/P2; final report in the closing commit | all | PF-2 | `run.py run --profile all && D make lint` |

## Linux compatibility and reliability

### Goal

**State:** active.

Make Asterinas a dependable Linux-compatible kernel for persistent VMs, development and service workloads, restricted processes, and a bounded virtual desktop. One reusable qualification harness proves each subsystem against a pinned Linux reference; ext4 is the first new subsystem through it.

"Port a subsystem" means reproduce the selected observable Linux contract, including failure, concurrency, permission, resource, and persistence behavior. It does not mean adopting Linux's internal architecture or source. A profile is qualified when every required case and assertion executes and passes, its negative controls detect failures, and previously qualified exact case IDs still pass.

Profiles, each a manifest in `test/qualification/profiles/` that names the profiles it inherits:

| Profile | Contract | Gate |
| --- | --- | --- |
| `vm-core` | Boot, process/FD/IPC/timer basics, ext2, virtio block/network/console/entropy, truthful diagnostics | G1 |
| `storage-ext4` | `ext4-ordered-v1`: format, ordered journaling, file operations, recovery, error propagation, Linux interoperability | G2 |
| `services` | Long-lived services and build/database workloads under SMP, bounded memory, churn, time and network disruption | G3 |
| `confined-services` | Credentials, Landlock, seccomp, selected namespaces, enforced cgroup v2 limits | G4 |
| `virtual-desktop` | Software-rendered Wayland session, PTY, evdev, DRM/KMS events and mediation on named QEMU devices | G5 |
| `virtual-audio` | Small ALSA PCM/control surface on virtio-snd | G5 (separate) |
| `arm64-vm` | `vm-core` and `storage-ext4` on AArch64 | G6 |

`services` inherits `vm-core` and `storage-ext4`; `confined-services` inherits `services`; `virtual-desktop` and `virtual-audio` inherit `vm-core`, `storage-ext4`, and the LC-41 credential contract. Passing isolated tests never waives an inherited failure.

### Decisions

**Owner (2026-11-25)**

- **O1 Backend.** Guests run under QEMU TCG on the macOS host (Homebrew `qemu-system-x86_64`); builds run in the dev container. Firecracker and KVM-only proof is **Needs environment**. The owner will provide a Linux environment; when it is recorded here, those entries become slices.
- **O2 Scope.** Every profile from the draft is sequenced in this campaign.
- **O3 CI.** No `.github/` edits. The campaign delivers local commands only; CI stages are in **Later**.
- **O4 Dependencies.** Third-party crates are allowed if they are `no_std`, `#![forbid(unsafe_code)]` or otherwise compliant with the rule that `unsafe` lives only in OSTD, MIT/Apache-2.0/BSD/MPL-2.0 licensed, maintained (a release or commit within 12 months), and pass the same tests as in-tree code. Kernel image size growth over 1% per crate parks the item. Each crate is named with its license and size delta in the commit body.

**Prescribed** (reason; what reverses it)

- **P1 Reference Linux.** v6.18.y LTS, latest stable tag when LC-03 starts, built from source through Nix `pkgsCross.gnu64` with `test/qualification/linux/config` checked in. Matches the kselftest 6.18 pin. The prebuilt 6.16.0 `vmlinuz` in the dev image is test equipment for LC-02, not a reference. If the source build fails three attempts, use the 6.16.0 binary with its `/proc/config.gz` (or the extracted IKCONFIG) as the reference and record the switch here. Changing the reference later is its own commit with before/after evidence.
- **P2 Harness.** Python 3.11+ standard library only, single entry point `test/qualification/run.py`, run on the host. Case truth and input pins live only in `contracts/` and `inputs.lock.json`; runlists and reports are generated from them. SCML stays the syscall flag format; contracts link to it.
- **P3 Build and boot split.** `run.py` builds through the dev container (`D` prefix), copies artifacts out with `cp -L` (the initramfs is a Nix-store symlink that does not exist outside the container) into `target/qualification/<run-id>/inputs/`, and boots QEMU on the host. Both kernels get the same machine: `-accel tcg -machine q35 -cpu max -smp 2 -m 1024` unless a profile states otherwise, `-no-reboot`, Linux with `panic=-1`.
- **P4 Result channel.** A dedicated second serial port carries `QUAL <run-id> <nonce> <json>` records and a final record with the manifest hash; the console is diagnostics only. The only copy of a log is never on a disk under test.
- **P5 Local storage contract.** virtio-blk, raw images, `cache=writeback` (FLUSH negotiated), a per-disk `serial=` checked in the guest against the manifest; `blkdebug` for I/O errors; `blklogwrites` for write logs, with crash cuts enumerated by the harness and replayed by the pinned `log-writes` `replay-log` built in the container. Storage profiles refuse to run unless both kernels report `write back` in `/sys/block/<dev>/queue/write_cache`. Supersedes the draft's Firecracker `cache_type: "Writeback"` requirement for local runs; that proof is NE-1.
- **P6 FLUSH not negotiated.** Keep the driver's success completion (the virtio spec allows a write-through device without FLUSH). The profile check in P5 keeps such a device from certifying durability. FUA is not modeled or claimed.
- **P7 Ext4 layout.** Pure format, checksum, extent, HTree, and JBD2 parsing/recovery logic live in `kernel/libs/aster-ext4-format` (`no_std`, a non-default workspace member so `make test` runs it on the host, following `kernel/libs/cpio-decoder`). I/O and VFS glue live in `kernel/core/src/fs/fs_impls/ext4/`. Ext2 stays separate and is not relaxed into nominal ext4.
- **P8 Writable gate.** Until LC-23, writable ext4 mounts exist only behind the `aster-core` cargo feature `ext4_rw_experimental`, off by default; without it, ext4 mounts read-only and refuses recovery-needed images. LC-23 deletes the feature.
- **P9 Evidence.** No external artifact storage. Bundles stay under `target/qualification/<run-id>/` (disposable). Each accepted slice's commit body records the run ID, lock hash, disposition counts per profile, and the replay command; minimized reproducers and fixture recipes are committed. Supersedes the draft's checked-in receipt index (it would be a second hand-maintained ledger).
- **P10 Deadlines.** Each profile fixes per-backend deadlines before its first candidate run: 10x the measured Linux-reference duration, minimum 60 s per case. They change only in a separate commit with before/after evidence on both kernels.
- **P11 Workloads.** All are pinned through `distro/nixpkgs.nix`. C0: a pthread stress probe in glibc and musl lanes, plus tmux. Services: nginx, curl (OpenSSL), dnsmasq, sqlite3, gcc and make building the SQLite amalgamation, chrony. Confinement: bubblewrap, and the Landlock `sandboxer` sample built from the reference source. Desktop: weston with the pixman renderer on the DRM backend, plus weston-terminal.
- **P12 Desktop device path.** First try the existing simpledrm with a boot framebuffer (`grub-rescue-iso`/multiboot2, `-vga std`), because PVH direct boot provides none. Implement virtio-gpu 2D only if that cannot satisfy weston's contract. Input comes from QMP `input-send-event` on virtio-keyboard/virtio-tablet; pixels come from QMP `screendump`.
- **P13 Audio.** `virtio-sound-pci` with `-audiodev wav`: playback is validated from the recorded file (frames and samples). Capture is qualified locally for frame counts and timing with the `none` backend; content-checked capture is NE-4.
- **P14 Performance.** TCG numbers are relative only. An optimization lands when the named PF-1 workload improves by at least 10% median over 5 trials with non-overlapping min/max ranges, and `run.py run --profile all` is green. Claims against Linux need KVM (NE-2). Budgets are frozen in PF-1 before any optimization. Never select seeds, discard timeouts, change fsync or security settings, or shrink the workload.
- **P15 Landlock.** ABI 6 exactly, per the draft. It restricts the installing thread and its future descendants, not existing siblings. Newer requested rights are rejected at admission, not downgraded. Never implemented as path-string prefix checks.
- **P16 AArch64 host.** HVF on this Apple-silicon host is real hardware virtualization, so LC-52 runs locally. If HVF is unavailable to QEMU, LC-52 moves to **Needs environment**.
- **P17 Libc.** Paired cases run the same executable on both kernels. The glibc lane is default (`pkgsCross.gnu64`, as the regression suite already uses); musl lanes (`pkgsCross.musl64`) exist where an item names them. Never compare binaries built against different libcs.
- **P18 Image.** Use the cached `asterinas/dev:0.19.0-20261012`, which AGENTS.md documents. `DOCKER_IMAGE_VERSION` says `0.19.0-20261119`; do not change either pin. Pull the `DOCKER_IMAGE_VERSION` tag only if the cached image is gone.

**Delegated** (bound; tie-break)

- **D1 Harness internals:** module layout, adapter and parser design, fixture recipes. Bound: P2, and the [Qualification rules](#qualification-rules). Tie-break: the smaller design that passes the controls.
- **D2 Case selection:** which upstream and native cases each contract includes. Bound: every case has an applicability record, and a selection never shrinks to hide a failure. Tie-break: include the case and record its disposition.
- **D3 Slice splitting:** an item whose acceptance takes over 15 min wall time, or whose diff exceeds about 1,500 lines, may be split into `LC-nnA/B`, with each part keeping one acceptance command. Rewrite **Sequence** in place.
- **D4 Crate adoption:** within O4, timebox evaluation to one hour per candidate. Tie-break: in-tree.
- **D5 Intentional divergence from Linux:** allowed only with a narrow test, retained transcripts, and a contract entry. Security-sensitive divergence needs an independent `review` lane.
- **D6 Missing ABI additions** (`recvmmsg`, `mincore`, `mlock`, `membarrier`, atomic KMS, virtio-gpu 2D): implement only when a named case or workload in the item needs them, with exact semantics, never as a successful no-op.
- **D7 Host process teardown:** on macOS the standard-library supervisor is fail-closed and leaf-only. Qualification adapters must run controlled VM processes that do not fork; teardown is `verified-empty` only for those leaf targets. Any observed fork, watcher failure, or scan failure makes the run `HARNESS_ERROR` rather than claiming recursive removal. Strict recursive containment for forking host processes needs a Linux cgroup backend and is not claimed on macOS.

### Baseline

Measured 2026-11-25 at `69015c7d3` on an Apple M5 Max (18 cores, 48 GiB) running macOS. No `/dev/kvm` in Docker or OrbStack. Container runs are arm64 Linux.

| Command | Result | Wall |
| --- | --- | --- |
| `D make test` | green | 19 s |
| `D make kernel BOOT_METHOD=vmm-direct BOOT_PROTOCOL=pvh` | green | 54 s |
| `D make initramfs` | green (Nix cache warm) | 4 s |
| `D make initramfs ENABLE_REGRESSION_TEST=true` | green after the glibc 2.42 wrapper renames and network include repairs in `4cfa3fa61` | not timed separately |
| Host QEMU TCG, Asterinas PVH ELF, `rdinit=/bin/echo` | reaches userspace; a panic when init exits is expected | 16 s |
| Host QEMU TCG, Linux 6.16.0 `vmlinuz` from the image, same initramfs | runs `/bin/echo`, exits with `panic=-1` | 3 s |
| `D make test` at `798fb7b12` | green | 13.6 s |
| `D make kernel BOOT_METHOD=vmm-direct BOOT_PROTOCOL=pvh` after `798fb7b12` | green | 28.7 s |
| `D make ktest ENABLE_KVM=0` at `798fb7b12` | **red**: one kernel-mode test, `realtime_clocks_store_fractional_seconds`, lacked wall-clock initialization; fixed in `914a9c245`, whose focused ktest is green | 1501.1 s; focused retest 92.5 s |
| `D make lint` at `798fb7b12` | green | 123.4 s |
| `D make run_kernel AUTO_TEST=regression ENABLE_KVM=0` at `914a9c245` | **red**, but boots and runs the regression suite for 354.7 s. The virtio sysfs topology case passes after `798fb7b12` and `62409f2c5`; the remaining red case is `setup_mount_nvme_ext2`: mounting `/dev/nvme0n1` returns `EINVAL` because the pre-existing generated `test/initramfs/build/nvme0n1.img` has a bad ext2 superblock (`dumpe2fs` exits 19). Treat as corrupted test input until disproved; do not delete or rewrite it without preserving evidence | 354.7 s |
| conformance suites | not yet timed | — |

Host tools present: QEMU 11.1.2 with `blkdebug`, `blklogwrites`, virtio-gpu/keyboard/tablet/sound; `qemu-system-aarch64`; Python 3.15.1. The container has e2fsprogs 1.47.0 (Ubuntu); fixtures use the Nix-pinned e2fsprogs instead. `vhost-vsock` is unavailable on macOS.

### Acceptance

Each item's command is in **Sequence**. Gates:

| Gate | Passes when |
| --- | --- |
| G0 credible harness | LC-02–LC-05: locked inputs verify; Linux self-comparison is all PASS; every H1 control is detected. Live-device and persistence controls are listed as pending, not passed. |
| G1 existing baseline | LC-06–LC-12: the ext2 and FD pilots pass on both kernels with `e2fsck -fn` clean; live controls and the omitted-sync control are detected; current passing regression cases are still passing. |
| G2 durable ext4 | LC-14–LC-25: the `storage-ext4` manifest publishes the feature/mount/storage-model matrix; independent fsck and semantic checks pass; cross-mount and cross-recovery pass both ways; the bounded crash campaign has no lost acknowledged durability; the SQLite and publication workloads pass. |
| G3 reliable services | LC-26–LC-38: the services scenario survives declared resource, process, clock, network, and storage disruptions. |
| G4 confined services | LC-39–LC-46: policy, namespace, and resource restrictions are enforced against unmodified consumers, and unsupported policy fails closed. |
| G5 virtual desktop | LC-47–LC-50: weston scenario with input, presentation, pixel, permission, and recovery evidence. Audio (LC-51) is gated separately. |
| G6 portability and performance | LC-52 runtime receipts on AArch64; PF-2 before/after evidence for each claimed improvement. |

Every gate requires: no unexplained panic, hang, lost acknowledgment, resource leak, or validator repair; a Linux reference failure blocks that comparison and never waives the candidate; the promoted artifact is the one tested, never a dirty or stale build; and the report states the tested bounds instead of claiming complete parity.

Item exits that must not be lost when a slice is narrowed:

- **LC-12:** the pilot covers create/read/write, sparse/truncate/extend zeroing, links/rename, permissions, file and directory sync, ENOSPC/EIO, clean remount, Linux readback, and offline validation; deliberate content and readiness defects are detected.
- **LC-09/LC-10:** write and flush failures reach the right callers on every descriptor; repeated errors, failed flushes, device loss, queue limits, partial I/O, and allocation failure never yield silent success or a panic; ext2, exfat, tmpfs, overlayfs, and virtiofs regressions stay green.
- **LC-16:** clean read-only interoperability with Linux-created fixtures; feature-policy tests; no accidental writable fallback; recursion, memory, and work bounded on corrupt input; unknown fields and flags are preserved, never cleared to gain acceptance.
- **LC-18:** replay obeys the JBD2 contract, is idempotent, survives interrupted recovery, and passes `e2fsck -fn` without repair. "Errors corrected" is a failure.
- **LC-23:** the full `ext4-ordered-v1` operation contract passes, including error paths and clean Linux readback. No supported path bypasses transactional accounting or falls back to unjournaled writes.
- **LC-25:** distinguishes acknowledged operations, whose durability is required, from unacknowledged work, where several recovered states are legitimate.
- **LC-27:** the pinned multithreaded glibc and musl workloads and the tmux supervisor survive cancellation, signals, fork/exec, and repeated churn without hangs, lost wakeups, or FD leaks.
- **LC-32:** bounded workloads converge to stable resource use, exhaustion follows the documented OOM policy, the supervisor stays responsive, and no acknowledged durability is lost.
- **LC-40:** an unprivileged workload cannot escape its limits; enforcement is measured with competing workloads against tolerances fixed before measuring, not by attribute readback. PSI, if exposed, is real.
- **LC-42/LC-43:** both denial and permitted operation are tested; unsupported actions and flags follow their documented failure, never allow-all.
- **LC-44/LC-45:** a confined tree cannot observe or modify resources outside its boundary; limits hold across namespace operations; teardown leaks no tasks, network state, mounts, or references. A namespace handle without isolation does not count.
- **LC-50:** unsupported graphics capabilities are reported accurately.

### Needs environment

These do not hold the campaign open. When the owner records a Linux x86-64 KVM host here, run them there with the same manifests.

| ID | Proof | Command on the Linux host |
| --- | --- | --- |
| NE-1 | Firecracker adapter: `vm-core` and `storage-ext4` under Firecracker with `cache_type: "Writeback"`, FLUSH negotiated, and its config file under the run directory | `run.py run --backend firecracker --profile storage-ext4` |
| NE-2 | KVM timing: services soak, M1 CPU-share tolerances under real time, timer latency, PF claims against Linux | `run.py run --backend qemu-kvm --profile services --soak 4h`; `run.py bench --backend qemu-kvm --profile perf-core --trials 10` |
| NE-3 | vsock device lifecycle (needs `vhost-vsock`) | `run.py run --backend qemu-kvm --profile n1-vsock` |
| NE-4 | Content-checked audio capture through a host loopback | `run.py run --backend qemu-kvm --profile virtual-audio --capture loopback` |

### Execution boundary and non-goals

**Authorized:** edits anywhere in this repository; local commits on `main` and lane branches; Docker runs of the dev image; host QEMU guests; fetching pinned public sources, Nix substitutes, and the pinned dev image; creating disposable images under `target/qualification/` and `.work/`.

**Forbidden:** pushing; issues, PRs, or messages anywhere; `.github/` edits (O3); installing or changing host packages; changing `rust-toolchain.toml`, `DOCKER_IMAGE_VERSION`, or `distro/nixpkgs.nix` pins; running formatters (`make format`); destructive operations on any path outside `target/qualification/<run-id>/` and `.work/`; inferring a test disk from device order instead of its serial; implementing anything below as a feature.

**Contract changes for the owner** (all additive): new `ext4` filesystem type (read-only until LC-23); new syscalls `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`, `seccomp`, `mincore`, `mlock`/`munlock`/`mlock2`, `membarrier`, `recvmmsg` (D6); `prctl(PR_SET_SECCOMP)`; `/sys/block/<dev>/queue/write_cache`; enforced cgroup v2 CPU and memory controllers that previously only stored values; fsync family now reports writeback errors it used to drop; new `test/qualification/` entry point and profile manifests.

**Non-goals** (no new implementation; inherited code stays and must not regress; unsupported operations return deliberate errors with truthful capability reporting):

- XFS, Btrfs, ZFS, network filesystem clients or servers; LUKS, dm-crypt, device-mapper, LVM, RAID, multipath (host-side test tools are allowed).
- Linux module or internal-API compatibility; mechanical translation of GPL code into MPL files.
- eBPF and its JIT, verifier, and observability (classic-BPF seccomp is in scope).
- nftables/iptables/NAT/bridging/overlays, VPN/IPsec, MPTCP, RDMA, DPDK, offloads, congestion-control breadth.
- Native GPU drivers, GPU compute, Wi-Fi/Bluetooth/USB breadth, cameras, physical laptops, suspend/hibernate, power management.
- 32-bit ABIs, new architectures beyond AArch64, new TEEs, a KVM host, a new VMM; runtime claims for RISC-V, LoongArch, confidential VMs, or physical hardware.
- Init systems, service managers, package managers, shells, compositors, sound servers, libc, TLS, Mesa, codecs, distribution images.
- Remote execution services, distributed schedulers, new build systems, custom hypervisors, a universal test DSL.
- Parity with all syscalls, every upstream test, every ioctl, bit-identical disk allocation, identical scheduler decisions, or identical packet traces.

**Deferred until admitted** (admission needs a named workload, a bounded contract, an upstream oracle, a resource cost, and its own item in **Sequence** through `campaign-plan` and preflight): ext4 fast commits, external journals, bigalloc, inline data, casefold, fscrypt, fs-verity, DAX, online resize, quotas, other journal modes, `orphan_file`, `metadata_csum_seed`, other geometries; io_uring, rseq, futex_waitv, PI futexes, userfaultfd, direct-I/O optimization, swap/zram, huge pages, NUMA; seccomp user notification, time namespaces, cgroup v1, SELinux/AppArmor/audit; TUN/TAP, `process_vm_readv/writev`, SysV shared memory, fanotify; PRIME/dma-buf/fences/render nodes, native audio, MIDI. Their absence is represented in the feature policy, never silently ignored. Never remove a required feature because its tests fail.

### Qualification rules

These bind every item; the controls are acceptance for LC-02, LC-05, LC-06, LC-11, and LC-13.

**Run lifecycle.** Resolve the profile and enumerate expected cases before boot. Preflight host tools, disk, memory, and CPU budget; a missing reference image or tool is `HARNESS_ERROR`, never a pass. Each run gets a new run ID, a private directory, cloned writable images, unique sockets and ports, and isolated network fixtures. Verify build identity, payload and manifest hashes, privilege identity, and the mounted filesystem, device, features, and options. The host enforces deadlines and can kill a hung guest. Validate completeness, then compare, then run validators, then publish the report atomically. Teardown removes every descendant process, VM, socket, mount, loop device, and image on success, failure, signal, and timeout. Default to one VM at a time; parallel guests are opt-in with isolated resources, and contention is recorded. Replays run offline from cached locked inputs.

**Lock.** `inputs.lock.json` pins the Asterinas commit and dirty-diff hash, Cargo lockfile, toolchain, build configuration, dev-image digest and kernel artifact hash; the Linux tag, config, command line, toolchain and boot artifact hash; initramfs, probe binaries, libc and tool versions; suite source revisions, archive checksums and applied patch hashes; e2fsprogs and mkfs recipes; QEMU version; host validators and injection tools; selected case IDs, contract revisions, expected subtests, exclusions, and normalization rules. Every `__asterinas__` branch in a test is inventoried; an environment adapter may change paths or setup, never the asserted observation.

**Case record.** ID, contract revision, area, item ID, upstream test or bug IDs; source, revision, license and patch hash; profile membership (required, discovery, deferred, excluded); prerequisites (arch, backend, privileges, config, flags, feature masks); procedure and expected subtests; comparison mode (exact, normalized, allowed-outcome, invariant) with every ignored field justified; deadline, budget, seed, iterations; required artifacts, validators, replay entry point.

**Comparison.** Compare return values, errno on failure, output bytes, permission decisions, namespace visibility, meaningful metadata, and committed application state. Never compare errno after success or unspecified bytes. Use raw-syscall probes for kernel contracts and libc probes separately. Normalize incidental IDs through relationship maps (parent/child, FD aliases, shared open-file descriptions, hard links, mounts, socket endpoints) and never drop whole fields. Enumeration order, timestamps, randomness, TCP sequence numbers, and scheduling get explicit invariants or allowed sets. Never normalize away missing entries, short I/O, permission failures, stale data, lost wakeups, lost durable state, or leaks. Concurrent cases check valid histories and progress, not interleavings. Crash cases compare logical durability obligations, not images or write indices. Linux is the oracle for its declared version and config, not a license to copy a known defect; disagreements are minimized, classified, and recorded under D5.

**Accounting.** Each selected case gets one terminal disposition: `PASS`, `FAIL`, `XFAIL`, `XPASS`, `SKIP_PREREQUISITE`, `UNSUPPORTED`, `TIMEOUT`, `PANIC`, `HARNESS_ERROR`, `REFERENCE_FAILURE`, or `NOT_RUN`, with candidate, reference, comparator, and validator results kept separately. The selected count equals the sum of dispositions; duplicates, unknown IDs, missing subtests, and contradictions invalidate the run. Case and subtest denominators are separate. Unselected, deferred, and excluded cases are reported with reasons. A missing Asterinas capability is `FAIL`, never `SKIP_PREREQUISITE`. `XFAIL` is visible debt; `XPASS` forces expectation review. Reruns keep the original result. Native reports are parsed (gtest XML/JSON, TAP/KTAP plans, Kirk JSON, xfstests outcomes), never a success sentence or a wrapper's exit code.

**Negative controls.** Each must fail its intended gate:

- H1, synthetic and Linux self-comparison (LC-02, LC-05): empty selection; zero matching gtests; all skipped; unknown or duplicate case; missing subtest or assertion; missing final record; truncated or malformed output; stale log; wrong run ID, payload, or manifest hash; deliberately wrong errno, byte, permission decision, or comparator result; guest panic and hang; host timeout; orphaned child; interrupted cleanup; full output disk; logging failure; missing artifact; checksum mismatch.
- Live (LC-06): wrong filesystem, wrong disk, failed mount, missing privileges, missing reference configuration.
- Persistence (LC-11): an omitted required sync is caught by at least one admissible crash cut.
- Suites (LC-13): each parser detects an empty or zero-execution run.

Changes to selectors, normalizers, validators, or expectations rerun the relevant controls. Controls are harness tests, not faults left in the release kernel.

**Persistence model.** Model accepted writes, completed writes, volatile cache, stable storage, and completed flushes; no FUA. Declare sector atomicity, torn-write granularity, and ordering. Guest process death, VM termination, backend I/O failure, and loss of volatile writes are separate fault classes; VM termination alone proves nothing about power loss. Record each kernel's own write log, enumerate cuts under the model, and compare logical obligations. Start with systematic cuts around sync and commit boundaries on short workloads; seeded stress comes after the omitted-sync control passes. Record explored schedules and bounds; a sampled campaign is never called exhaustive. Crash images stay immutable: candidate recovery, Linux recovery, and `e2fsck` each get their own clone.

**Provenance.** Record source, license, notices, and modifications for anything adapted. Upstream suites are fetched through Nix, not vendored. Never translate GPL implementation code under an MPL header; KUnit invariants are re-expressed through Asterinas APIs and native tests, with the original and derived IDs linked in the regression registry. Regression records cite the upstream fix and test revision, applicability (now, future feature, Linux-internal, excluded), the minimal witness, and the native ID; establish sensitivity on pre-fix and post-fix Linux where practical. Start from verified merged ext4/JBD2 fixes and existing blocked cases; claim no corpus until its source and applicability are recorded.

**Per-item method.** Inventory what exists; define the finite contract; prove the test on the oracle; capture an Asterinas failure with a minimized reproducer; design ownership, lock order, rollback, bounds, and feature discovery; implement the smallest complete vertical behavior including negative cases; validate host, kernel, paired, fault, and application layers; update SCML, the book's compatibility pages, the regression registry, and the profile manifest. Kernel code stays safe Rust in its crate layer; a new `unsafe` primitive needs an OSTD design and an independent `review` lane. Recheck old blocklist entries rather than assuming they still fail.

### Reference

Verified at `69015c7d3`:

| Area | Location | Fact |
| --- | --- | --- |
| Filesystems | `kernel/core/src/fs/fs_impls/` | cgroupfs, configfs, devpts, devtmpfs, exfat, ext2, overlayfs, procfs, pseudofs, ramfs, sysfs, tmpfs, virtiofs; no ext4/JBD2 |
| Writeback errors | `kernel/core/src/vm/page_cache/mod.rs:768` | TODO: writeback EIO is not recorded for later sync |
| Flush | `kernel/core/comps/virtio/src/device/block/device.rs:449` | flush completes successfully when FLUSH is not negotiated |
| Ext2 test disk | `kernel/core/src/fs/fs_impls/ext2/test_utils.rs` | memory disk with flush and error handling; not a crash model |
| Modern ABI | `kernel/core/src/syscall/arch/x86.rs:385-445` | openat2, clock_adjtime, pidfd_*, fsopen, clone3, epoll_pwait2 are dispatched; no landlock, seccomp, mincore, membarrier, mlock |
| cgroups | `kernel/core/src/fs/fs_impls/cgroupfs/controller/cpu.rs:232,290`; `memory.rs:36,41` | CPU weight/quota stored with a warning, not enforced; memory attributes unimplemented |
| Namespaces | `kernel/core/src/process/namespace/`; `kernel/core/src/net/net_ns.rs` | mount/UTS/IPC/cgroup present; PID/user uneven; network namespace is an init singleton only |
| LSM | `kernel/core/src/security/lsm/modules/` | capability and Yama only |
| DRM | `kernel/comps/drm/src/ioctl/kms.rs:69` | atomic modesetting capability rejected |
| Firecracker | `tools/firecracker_args.sh` | echo marker, no drives, config defaults to `/tmp/fc-vm.json` |
| Conformance | `test/initramfs/src/conformance/run_conformance_test.sh` | LTP, gVisor, kselftest (Nix pin v6.18), pjdfstest, xfstests (`XFSTESTS_FS_TYPE ?= ext2`) |
| Benchmarks | `test/initramfs/src/benchmark/common/prepare_host.sh:16` | Linux 6.16.0 binary cache; ext2 features disabled for fairness |
| Regression build | `test/initramfs/src/regression/Makefile`, `test/initramfs/nix/default.nix` | Nix cross `x86_64-unknown-linux-gnu`, glibc 2.42 |
| Syscall flags | `book/src/kernel/linux-compatibility/syscall-flag-coverage/` | SCML files |

The book's [Linux compatibility pages](../book/src/kernel/linux-compatibility/README.md) and [historical roadmap](../book/src/kernel/roadmap.md) are discovery inputs, not a ledger: some calls they list as unsupported are dispatched today.

External specifications: [ext4 format](https://docs.kernel.org/filesystems/ext4/index.html), [JBD2](https://docs.kernel.org/filesystems/ext4/journal.html), [ext4 orphans](https://docs.kernel.org/filesystems/ext4/orphan.html), [ext4 mount options](https://docs.kernel.org/admin-guide/ext4.html), [dm-log-writes](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html), [log-writes replay](https://github.com/josefbacik/log-writes), [Virtio 1.2](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html), [Firecracker block caching](https://github.com/firecracker-microvm/firecracker/blob/main/docs/api_requests/block-caching.md), [Landlock](https://docs.kernel.org/userspace-api/landlock.html), [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html), [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), [DRM uAPI](https://docs.kernel.org/gpu/drm-uapi.html), [input event codes](https://docs.kernel.org/input/event-codes.html), [kselftest](https://docs.kernel.org/dev-tools/kselftest.html), [xfstests](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/), [e2fsprogs](https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/), [syzkaller OS support](https://github.com/google/syzkaller/blob/master/docs/adding_new_os_support.md), [Linux license rules](https://docs.kernel.org/process/license-rules.html). Repository license policy: [`.licenserc.yaml`](../.licenserc.yaml).

## Later

- **CI progression** (O3): add per-change manifest/parser controls; after G1, a bounded paired ext2/core suite on KVM; after G2, the ext4 short list and durability controls; scheduled longer runs. Started by the owner with "fix ci".
- **Focused upstream adapters:** packetdrill, selected blktests, libdrm/IGT, libinput, minimized syzkaller reproducers, and full coverage-guided syzkaller integration, each admitted by a named failure class.
- **Newer-Linux discovery lane:** run profiles against the latest mainline, independent of the qualification reference.
- **Upstream fix review:** a process for reviewing new ext4/JBD2 and subsystem fixes for applicability, with no recurring task installed.
