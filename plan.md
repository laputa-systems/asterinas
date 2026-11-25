# Asterinas Linux Compatibility and Reliability Campaign

## Status and resume point

- **Updated:** 2026-11-25.
- **State:** planned; implementation and qualification have not started under this campaign.
- **Audited baseline:** `ea1c0d1d9724d78f2899e864177a1a32d092a6dd`.
- **Evidence available for this document:** repository source inspection and upstream documentation.
  No kernel build, guest execution, benchmark, or fault campaign was performed for this plan.
- **First task:** H0, inventory and lock the actual baseline.
- **First delivery:** an honest paired ext2 qualification run, followed by the ext4 storage profile.
- **Authoritative scope:** this document for this campaign; [AGENTS.md](AGENTS.md) and the
  [coding guidelines](book/src/to-contribute/coding-guidelines/README.md) govern implementation.

Keep this section current with the active work-package ID, last verified source and artifact hashes,
evidence location, unresolved failures, and the next executable action.
An implementation commit, a passing build, and a qualified capability are different milestones.
Do not mark a work package complete without its exit evidence.

Navigate to [scope](#4-explicit-scope-boundaries),
[harness](#5-one-reusable-qualification-harness),
[work packages](#7-work-packages-and-exit-evidence),
[delivery gates](#8-delivery-gates-and-completion-rules),
or [agent execution](#9-execution-protocol-for-implementation-agents).

## 1. Objective

Make Asterinas a dependable Linux-compatible kernel for persistent virtual machines,
ordinary development and service workloads, restricted processes, and a bounded virtual desktop.
Build one reusable qualification harness that supports implementing Linux subsystem contracts
in Asterinas's safe-Rust architecture.
Ext4 is the first new subsystem delivered through that harness.

The campaign belongs entirely to this repository.
Its specifications, test programs, fixtures, and evidence must be understandable and reproducible
without another operating-system distribution, a particular init system, package manager,
shell implementation, or sibling checkout.
Use small standalone reproductions and independently pinned reference applications.
Distribution policy and application-specific workarounds do not belong in the kernel.

“Port a subsystem” means reproduce the selected observable Linux contract,
including failure, concurrency, permission, resource, and persistence behavior.
It does not require adopting Linux's internal architecture, algorithms, data structures,
or kernel source compatibility.
The campaign has finite supported profiles and explicit exclusions;
it is not a promise to implement every Linux feature.

Success means a selected profile has reproducible evidence,
all its required cases execute and pass,
its negative controls detect failures,
and previously qualified behavior remains qualified.
Finite tests and bounded models do not prove the absence of every possible defect.

## 2. What already exists, and what inspection actually establishes

These observations refer to the audited baseline above.
Revalidate them in H0 before changing code.
Links identify implementation or infrastructure, not passing runtime evidence.

| Area | Observed baseline | Consequence |
| --- | --- | --- |
| Architecture | [AGENTS.md](AGENTS.md) requires safe Rust in the upper kernel and confines unsafe implementation to OSTD. | Preserve the framekernel boundary and existing crate layering. |
| Active CI | [ci.yml](.github/workflows/ci.yml) runs host unit tests, builds PVH, and checks a Firecracker userspace marker; [lint.yml](.github/workflows/lint.yml) runs lint. | This is not storage, network, kernel-test, or full conformance qualification. |
| Firecracker launcher | [firecracker_args.sh](tools/firecracker_args.sh) boots an echo marker with no attached drives. | Add real workload, disk, network, and completion contracts. |
| Conformance | [run_conformance_test.sh](test/initramfs/src/conformance/run_conformance_test.sh) dispatches LTP, gVisor, kselftest, pjdfstest, and xfstests. | Extend this packaging and corpus rather than replacing it. |
| Filesystems | [fs_impls](kernel/core/src/fs/fs_impls/mod.rs) includes ext2, exfat, tmpfs, overlayfs, virtiofs, and pseudo filesystems; no ext4/JBD2 implementation is registered. | Preserve existing coverage and add a separately qualified ext4 implementation. |
| Ext2 fixtures | [test_utils.rs](kernel/core/src/fs/fs_impls/ext2/test_utils.rs) has a memory disk with flush/error handling. | Extend it; immediate writes to one memory image are not a power-loss model. |
| Writeback | [page_cache](kernel/core/src/vm/page_cache/mod.rs) has an explicit TODO to retain asynchronous writeback errors for later synchronization, and documents missing pressure-driven flush/eviction machinery. | Error accounting and reclaim are shared work packages, not ext4-only details. |
| Virtio storage | [block device](kernel/core/comps/virtio/src/device/block/device.rs) completes flush successfully when FLUSH was not negotiated. | Qualification must establish the actual persistence contract, including backend configuration. |
| Modern ABI | [x86 dispatch](kernel/core/src/syscall/arch/x86.rs) already includes openat2, clone3, pidfds, epoll_pwait2, clock adjustment, and modern mount interfaces. | Audit their semantics; do not list them as absent merely because old documentation does. |
| Resource controls | [CPU controller](kernel/core/src/fs/fs_impls/cgroupfs/controller/cpu.rs) stores weight/quota without enforcing them; [memory controller](kernel/core/src/fs/fs_impls/cgroupfs/controller/memory.rs) has unimplemented attribute access. | Successful configuration/readback is not effective resource isolation. |
| Namespaces | [nsproxy](kernel/core/src/process/namespace/nsproxy.rs), [PID namespace](kernel/core/src/process/namespace/pid_ns.rs), and [user namespace](kernel/core/src/process/namespace/user_ns.rs) show uneven support. | Separate existing mount/UTS/IPC/cgroup behavior from new PID/user/network namespace work. |
| Devices and graphics | [device model](kernel/core/src/device/model.rs), [DRM](kernel/comps/drm/src), [simpledrm](kernel/comps/simpledrm/src), and [evdev](kernel/core/src/device/evdev) already exist. | Qualify lifecycle and event semantics instead of starting a second device framework. |
| Graphics limits | [DRM file](kernel/comps/drm/src/file.rs) rejects reads and reports unconditional readiness; [KMS](kernel/comps/drm/src/ioctl/kms.rs) rejects atomic capability. | Opening a DRM node or drawing a framebuffer does not qualify compositor support. |
| Existing differential assets | [benchmark runner](test/initramfs/src/benchmark/bench_linux_and_aster.sh) runs both Linux and Asterinas. | Reuse build assets and workloads, while making qualification identity and comparison stricter. |

The [Linux compatibility documentation](book/src/kernel/linux-compatibility/README.md)
and historical [roadmap](book/src/kernel/roadmap.md) are discovery inputs.
They are not the campaign's completion ledger.
For example, some documented unsupported calls already have dispatch entries,
and existing networking code contains IPv6 paths.
Neither a dispatch entry, a TODO, an old blocklist, nor a syscall count establishes current correctness.

## 3. Supported profiles and priority

Profiles separate delivery gates; later profiles do not delay an earlier one.
Each becomes an exact machine-readable manifest during implementation.
All profiles use independently pinned userspace payloads and explicit privilege identities.

| Profile | Intended contract | Target and priority |
| --- | --- | --- |
| `vm-core` | Boot, process/FD/IPC/timer fundamentals, ext2 baseline, virtio block/network/console/entropy, truthful diagnostics. | First: x86-64 Linux host with KVM, Asterinas PVH on Firecracker. |
| `storage-ext4` | Qualified ext4 format, ordered journaling, file operations, recovery, error propagation, and Linux interoperability. | First major new subsystem; same headless VM target. |
| `services` | Long-lived network services and build/database workloads under SMP, bounded memory, process churn, and time/network disruption. | Required general-purpose reliability milestone. |
| `confined-services` | Credentials, Landlock, seccomp, selected namespaces, and enforced cgroup v2 resource limits. | Required restricted-workload milestone; no container-brand certification. |
| `virtual-desktop` | Software-rendered Wayland session, terminal/PTY, evdev, DRM/KMS events and device mediation on a named virtual device set. | Later, independently qualified QEMU device profile. |
| `virtual-audio` | Small ALSA PCM/control surface with a named virtual sound device and independently observed playback/capture. | Later optional profile, after the device and memory foundations. |
| `arm64-vm` | The same selected contracts on a supported AArch64 VM boot/device configuration. | Later portability gate; build-only results never substitute for runtime evidence. |

Retain QEMU as a test backend for devices or injection mechanisms that Firecracker does not expose.
It is not a second harness or a requirement to replace the primary headless target.
PVH is an x86 boot choice, not the AArch64 boot contract.
Preserve existing architecture and driver builds where practical;
do not claim new runtime support for RISC-V, LoongArch, confidential VMs, or physical hardware.

### 3.1 Highest-value work, in order

| Order | Work | Why it belongs |
| --- | --- | --- |
| 1 | Trustworthy harness, exact baseline, ext2 pilot. | Every later completion claim depends on reliable evidence. |
| 2 | Shared writeback/block correctness and ext4. | Persistent data and recoverable state are foundational. |
| 3 | Threads, signals, mappings, readiness, and process lifecycle. | These support libc, language runtimes, shells, databases, and supervision. |
| 4 | Reclaim, OOM behavior, scheduler/resource accounting, and cgroup enforcement. | A bootable guest must remain usable under sustained work and exhaustion. |
| 5 | TCP/UDP/Unix sockets, dual-stack control plane, netlink, clocks, and device lifecycle. | Services need correct reconnection, configuration, cancellation, and diagnostics. |
| 6 | Landlock, seccomp, credentials, and selected namespace isolation. | Restricted processes need effective, testable boundaries. |
| 7 | Virtual desktop kernel interfaces, then optional virtual audio. | Reuse the existing device foundation without admitting a broad hardware project. |
| 8 | Measured performance, portability, and justified optional ABI additions. | Optimize qualified behavior and admit new surface only for a demonstrated workload. |

Dependencies may justify small prerequisite fixes ahead of this order.
They do not justify finishing an entire unrelated subsystem before ext4.

## 4. Explicit scope boundaries

### 4.1 Excluded from this campaign

| Area | Exclusion and boundary |
| --- | --- |
| Other production filesystems | XFS, Btrfs, ZFS, new NFS/SMB/Ceph clients or servers, and a general filesystem expansion project. Existing ext2/exfat/tmpfs/overlayfs/virtiofs remain regression obligations. |
| Encrypted/stacked block storage | LUKS, dm-crypt, guest device-mapper, LVM, software RAID, multipath, and storage-management tooling. Host-side dm-log-writes or fault tools are permitted test equipment. |
| Kernel source/module compatibility | Linux binary modules, Linux internal API/locking/object-layout compatibility, embedding Linux in the kernel, and mechanically translating its C implementation as a default strategy. |
| General programmable kernel | Full eBPF, its JIT/verifier/helper ecosystem, BPF-based observability, and arbitrary kernel instrumentation compatibility. Seccomp classic BPF is explicitly in scope. |
| Broad network appliance features | General nftables/iptables/NAT/bridging/overlay parity, kernel VPN/IPsec, MPTCP, RDMA, DPDK, specialized NIC offload, and every congestion-control algorithm. |
| Broad physical hardware | Native GPU driver families, GPU compute, Wi-Fi/Bluetooth/USB breadth, camera/video-capture stacks, physical laptop bring-up, suspend/hibernate, and power-management parity. Preserve already supported drivers. |
| Platform breadth | 32-bit/legacy ABIs, new CPU architectures, new TEE platforms, a KVM host implementation, and a new VMM. |
| Userspace redesign | An init system, service manager, package manager, shell, compositor, sound server, libc, crypto/TLS stack, Mesa port, codec implementation, or distribution image project. Existing applications are test consumers. |
| Test infrastructure expansion | A remote execution service, distributed scheduler, new package/build system, custom hypervisor, or universal testing DSL. Reuse repository tooling. |
| Unbounded parity claims | All Linux syscalls, every upstream test, every ioctl, bit-identical disk allocation, identical scheduler decisions, or identical TCP packet traces. |

Exclusion means no new implementation under this campaign.
It does not authorize deleting inherited code or allowing a shared change to regress it.
Unsupported operations still require deliberate errors, truthful capability reporting,
and safe rejection tests where they cross an implemented boundary.
Documented Linux advisory/no-op semantics remain valid;
distinguish them from claiming an unenforced security, resource, lifecycle, or durability effect.

### 4.2 Deferred unless a bounded profile explicitly admits them

- Ext4 fast commits, external journals, bigalloc, inline data, casefold, fscrypt, fs-verity,
  DAX, online resize, quotas, other journaling modes, live ext2/ext3 migration,
  `orphan_file`, `metadata_csum_seed`, and additional block/inode geometries.
  Their absence must be represented in the feature policy; never silently ignore required semantics.
- io_uring, rseq, futex_waitv, userfaultfd, advanced asynchronous/direct-I/O optimization,
  swap/zram, huge pages, and NUMA policy breadth.
  Correct fallbacks may make some unnecessary for the selected applications.
- Seccomp user notification, time namespaces, cgroup v1, full controller breadth,
  SELinux/AppArmor/audit compatibility, and general container-runtime certification.
- TUN/TAP for an identified userspace network workload, additional socket options,
  `process_vm_readv/writev`, System V shared memory, fanotify, and extra debugger APIs.
- GPU acceleration protocols, render-node/PRIME/dma-buf/synchronization breadth beyond the
  selected desktop contract, native audio drivers, MIDI, and professional audio features.

Admission requires a named workload, a bounded ABI/feature contract, an upstream oracle,
dependencies, resource cost, and a separate exit gate recorded here.
Do not add a feature merely because a larger upstream test suite contains tests for it.
Do not remove a required feature because its tests fail.

## 5. One reusable qualification harness

### 5.1 Reuse first, then generalize from working slices

Reuse [test/initramfs](test/initramfs), its Nix packages and regression programs,
[OSDK](osdk), kernel `ktest`, existing VM launch configuration,
and the existing benchmark workloads.
Use [test/nixos](test/nixos) application scenarios where helpful,
but do not require a complete distribution build for a standalone kernel test.

Implement a small host orchestrator in Python using the standard library where practical,
plus the existing build and VM tools.
Keep guest probes in the languages already used by their suites;
standalone C syscall probes and native Rust `ktest` are appropriate.
Do not build a generic framework before proving a filesystem slice
and one small process/FD slice with it.

The following is a **proposed layout, not existing functionality**:

| Path | Responsibility |
| --- | --- |
| `test/qualification/run.py` | Single host entry point: preflight, build/resolve, run, compare, replay, summarize. |
| `test/qualification/inputs.lock.json` | Exact source, configuration, binary, tool, suite, and patch identities. |
| `test/qualification/profiles/` | Required contracts, environments, device sets, and fixed budgets. |
| `test/qualification/contracts/` | Stable case IDs, assertions, applicability, comparison rules, and regressions. |
| `test/qualification/adapters/` | Small suite parsers and Firecracker/QEMU launch/collection adapters. |
| `test/qualification/fixtures/` | Reproducible image/network/input/fault recipes and bounded seed corpora. |
| `test/qualification/README.md` | Operator guide, supported hosts, exact commands, resource costs, failure replay. |
| `target/qualification/<run-id>/` | Untracked run evidence, with checksums and explicit retention/export. |

Add a top-level Makefile wrapper only after the entry point works.
Keep case truth and input pins in one place; suite runlists and reports should reference or be
generated from that source instead of introducing a second manually maintained applicability list.
SCML remains the existing syscall flag description format;
link contracts to it and improve it instead of creating a competing ABI language.

### 5.2 Reference and input lock

H0 selects one maintained upstream Linux reference and records its exact source commit,
configuration, compiler/container, and resulting boot image hash.
Record test-source revisions separately from the reference kernel revision.
The current kselftest package uses v6.18 while existing benchmark preparation uses Linux 6.16.0;
these are reusable assets, not interchangeable evidence or an implicit reference policy.

Lock at least:

- Asterinas commit, local patch/diff hash if any, Cargo lockfile, compiler, build configuration,
  image/container digest, and kernel artifact hash.
- Linux source commit, configuration and command line, toolchain, modules if required by a test,
  and boot artifact hash; tests requiring unavailable configuration are not reference passes.
- Guest payload/initramfs/root hashes, each probe binary, libc/tool versions,
  suite source revisions, source archive checksums, and applied test patch hashes.
- e2fsprogs/mkfs configuration, VMM binary/version, host-side validators and injection tools.
- Selected case IDs, contract revisions, expected subtests, exclusions,
  normalization rules, and fixture recipes.

Use the same guest test executable on both kernels for each paired case.
Have separate explicit musl and glibc lanes when needed;
do not compare an Asterinas-musl binary with a Linux-glibc binary and attribute every difference to the kernel.
Existing `__asterinas__` branches must be inventoried;
an environment adapter may change paths/setup, but cannot weaken the observation being asserted.

A newer-Linux discovery lane may run independently.
Changing the qualification reference or test pins is a separate reviewed change with before/after evidence.
Never fix a failing comparison by silently moving the reference, changing the libc,
turning off the relevant Linux feature, or changing kernel options on only one side.

### 5.3 Run lifecycle and isolation

1. Resolve the frozen profile and enumerate all expected cases before boot.
2. Check host KVM, tools, disk/memory/CPU budget, and required device capabilities.
   Missing KVM or a reference image is a blocked run, not a pass.
3. Create a new run ID, private output directory, independently cloned writable images,
   unique sockets/ports, and isolated host network fixtures.
4. Boot the selected kernel with equivalent CPU, RAM, workload, and device contracts.
   Record unavoidable backend differences instead of comparing different machines as if identical.
5. Verify build identity, payload and manifest hashes, privilege identity,
   actual mounted filesystem/device/features/options, and required capabilities.
6. Run cases with guest diagnostics and host-enforced deadlines.
   The host must be able to terminate the guest even if the kernel or transport hangs.
7. Collect native suite output, structured case events, exit status,
   an end-of-run record bound to this run ID and manifest, and independent artifact hashes.
8. Validate completeness, compare the contract, run independent validators,
   preserve failure artifacts, then publish the final report atomically.
9. Tear down all descendants, VM processes, containers, sockets, mounts, loop devices,
   namespaces, and temporary devices on success, failure, signal, and timeout.

Use serial as the initial control/result channel.
An additional artifact disk or vsock transport can improve throughput later,
but testing vsock must not depend on vsock working to collect the result.
Never keep the only test log on the filesystem being crash-tested.

Destructive tests operate only on newly allocated disposable images
or explicitly bound test devices checked against the manifest.
Never infer a target from `/dev/vdX` order, an unverified mountpoint, or a stale path.
Preserve immutable base fixtures and crash evidence before replay or repair.

Default to one VM workload at a time with an explicit host CPU budget.
Parallel execution is an opt-in bounded setting with isolated resources.
Record oversubscription and host contention; do not quietly increase timeouts until failures disappear.
Do not require network access during a replay when locked inputs are already cached.

### 5.4 Case contracts and semantic comparison

Each case record must contain:

| Field group | Required information |
| --- | --- |
| Identity | Stable ID, contract revision, subsystem, work-package ID, upstream test/bug IDs. |
| Provenance | Source URL/revision, license, retained notices, patch hash, import/derivation rationale. |
| Scope | Profile membership and whether required, optional discovery, deferred, or excluded. |
| Prerequisites | Architecture, device/backend, privileges, configuration, syscall flags, filesystem feature masks. |
| Procedure | Setup, workload, observations/assertions, teardown, expected subtests or assertion inventory. |
| Comparison | Exact, normalized, allowed-outcome, or invariant mode; every ignored field justified. |
| Execution | Deadlines, memory/CPU/disk budget, seed, schedules, iteration count. |
| Evidence | Required artifacts, validator commands, expected failure signatures, replay entry point. |

Compare defined return values, errno on failure, output bytes, permission checks,
namespace visibility, meaningful metadata, and committed application state.
Do not compare errno after successful calls or unspecified output bytes as though they were defined.
Use raw syscall probes where libc emulation would obscure the kernel contract,
and libc-level probes separately for application behavior.

Normalize incidental IDs through consistent relationship maps:
for example, parent/child identity, descriptor aliases, shared open-file descriptions,
hard links, mount identities, and socket endpoints must remain distinguishable.
Do not remove entire metadata fields just because their numeric values differ.
Directory enumeration order, timestamps, random bytes, TCP sequence values,
and scheduler choices need explicit invariants or allowed sets.
Never normalize away missing entries, short I/O, permission failures, stale data,
lost wakeups, lost durable state, or resource leaks.

Concurrent cases use synchronization and valid histories/progress properties,
not identical interleavings.
Clock/timer cases distinguish semantic correctness from scheduling latency.
Crash cases use the same logical durability obligations across kernels,
not byte-identical disk images or matching physical write indices.

Linux is an oracle for the declared version/configuration, not authority to copy a known defect.
When documentation, Linux behavior, or versions disagree, retain the transcripts,
minimize the discrepancy, classify it, and record any intentional divergence with a narrow test.
A stricter answer is not automatically ABI-compatible;
security-sensitive deviations require a stated contract rather than concealed normalization.

### 5.5 Accounting and false-pass prevention

Preserve native suite outcomes, then assign each selected case one terminal comparison disposition:

`PASS`, `FAIL`, `XFAIL`, `XPASS`, `SKIP_PREREQUISITE`, `UNSUPPORTED`,
`TIMEOUT`, `PANIC`, `HARNESS_ERROR`, `REFERENCE_FAILURE`, or `NOT_RUN`.

Keep candidate, reference, comparator, and independent-validator results separately within that record.
The selected-case count must equal the sum of terminal dispositions;
duplicates, unknown IDs, missing subtests, and contradictory records invalidate the run.
Also report discovered-but-unselected, deferred, and excluded cases with reasons.
Case counts and subtest counts are separate denominators.

A required capability missing from Asterinas remains an unfulfilled requirement;
it cannot be reclassified as an environmental skip to qualify the profile.
An unavailable Linux prerequisite produces no usable oracle for that case.
XFAIL is visible debt, not a pass; XPASS triggers expectation review.
Reruns retain the original result and test identity instead of erasing intermittent failures.
Every required case and its required assertions must actually pass to promote a profile.

Adapt native reports rather than scraping a success sentence:
gtest subtest inventory/XML or JSON, TAP/KTAP plans, Kirk JSON, and xfstests case outcomes.
Audit current wrappers for empty gtest filters, zero-execution runs, skip handling,
pipeline/logger errors, missing helpers, and blocklist bypass behavior.
A zero exit code from a wrapper is insufficient.

Before trusting the harness, make each of these controls fail the intended gate:

- Empty selection; zero matching gtests; all cases skipped.
- Unknown/duplicate case; missing assertion/subtest; missing final record.
- Truncated or malformed output; old logs; wrong run ID, payload, or manifest hash.
- Wrong filesystem, wrong disk, failed mount, missing privileges, or missing reference configuration.
- Deliberately incorrect errno, payload byte, permission decision, or semantic comparator result.
- Guest panic/hang, host timeout, orphaned child process, and interrupted cleanup.
- Full output disk, logging failure, missing artifact, or checksum mismatch.
- A deliberately omitted required sync, detected by at least one admissible persistence-loss schedule.

Stage these controls with their required machinery.
H1/G0 validates protocol, accounting, parser, supervisor, and comparator controls
using synthetic result fixtures and Linux self-comparison.
H2/H3 validates live guest, mount, device, and workload controls.
S0/G1 validates omitted-sync and lost-durability sensitivity
using the independently checked persistence model.
Keep later controls explicitly unexecuted until their stage runs;
mocked output does not qualify a live storage contract.

These are harness regression tests, not permanent faults in the release kernel.
Changes to selectors, normalizers, validators, or expectations require the relevant controls to run again.

### 5.6 Evidence and reproducibility

Each result bundle contains the lockfile, full selected manifest,
host CPU/model/microcode/kernel and accelerator details,
vCPU/RAM/device configuration, negotiated features,
effective filesystem/mount settings, seed and workload trace,
native and normalized results, panic/serial/supervisor logs,
and all independent-validator output.
Record dirty-tree identity honestly; a source SHA alone cannot identify an uncommitted build.

For storage failures retain the immutable input image, write/fault log,
crash cut, recovered clones, and content checksums or an equivalent lossless reconstruction recipe.
For network/device failures retain packets or input/event traces and peer configuration.
For resource failures retain allocation/accounting/pressure measurements and survivors' progress.
Provide one replay command tied to these artifacts.

Commit small minimized reproducers and recipes, not enormous generated disk images or logs.
Export important evidence to durable artifact storage with checksums and retention metadata.
A path in an expired workspace is not enduring qualification evidence.
Keep a compact checked-in status/receipt index pointing to retained evidence,
without maintaining a second hand-edited pass-count dashboard.

### 5.7 Test pyramid and upstream reuse

| Layer | Mechanism | Obligation |
| --- | --- | --- |
| Pure structures/algorithms | Host Rust tests, properties, parser fuzzing, bounded models. | Invalid inputs, bounds, arithmetic, serialization, invariants. |
| Kernel components | Existing `ktest`, controlled mock devices, allocation/I/O fault injection. | State transitions, cleanup, locking, lifetimes, errors. |
| Userspace ABI | Existing LTP/gVisor/kselftest/pjdfstest/xfstests plus paired probes. | Same operation and meaningful observations on both kernels. |
| Persistence/recovery | Durable/volatile storage model, traced replay, independent e2fsprogs. | Required durability and structural consistency at admissible crash cuts. |
| Stress/resource isolation | SMP, process churn, bounded memory, slow peers, injected errors. | Progress, containment, limits, no leak or silent corruption. |
| Applications | Pinned SQLite, compiler/build, HTTP/socket service, shell/PTY and compositor scenarios. | Real workload behavior without kernel-specific assertion weakening. |
| Performance | Existing fio/lmbench/iperf3/schbench/application assets. | Same work, resource limits, security and durability settings; validated results. |

Linux KUnit tests depend on Linux internals.
Run the original test on Linux where useful, extract its invariant,
and express that invariant through Asterinas's APIs and native tests.
Do not reproduce Linux internals just to make a KUnit function compile.
Keep original and derived test identities linked in the regression registry.

Use existing test sources before writing a new corpus.
Candidates for later focused adapters include packetdrill, selected blktests,
libdrm/IGT, libevdev/libinput, and minimized syzkaller reproducers.
Validate prerequisites and test assumptions before treating them as usable here.
Full coverage-guided syzkaller needs executor, coverage, crash detection, resource handling,
and minimization integration; it is a later bounded task, not an automatic consequence of Linux ABI support.
CrashMonkey/ACE and xfstests-bld are sources of methodology and fixtures,
not mandatory new runtime dependencies or claims that their entire workflows already run.

### 5.8 Persistence model

Model accepted writes, completed writes, volatile cache contents,
stable storage, completed flushes, and FUA only where the device contract actually supports it.
The current block BIO vocabulary is Read/Write/Flush;
do not invent a FUA requirement or claim FUA support for the initial virtio profile.
Declare sector atomicity, torn-write granularity, ordering constraints,
failure behavior, and which storage layers the model covers.

Firecracker storage qualification explicitly selects `cache_type: "Writeback"`,
checks FLUSH negotiation, observes flush delivery and error propagation,
and records host backing-file/filesystem/device assumptions.
Its default `Unsafe` mode does not advertise FLUSH.
A missing flush feature is not automatically a driver bug on every device,
but that configuration cannot certify this durability profile without another documented stable-write contract.
See the [Firecracker cache contract](https://github.com/firecracker-microvm/firecracker/blob/main/docs/api_requests/block-caching.md).

Guest process death, VM termination, backend I/O failure, and loss of volatile host/device writes
are different fault classes.
VM termination alone cannot establish host-power-loss safety.
QEMU blkdebug can exercise I/O failures;
host/Linux [dm-log-writes](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html)
and controlled durable/volatile models can exercise persistence ordering.
Keep these tools outside the guest kernel feature scope.

Record each implementation's own physical write trace.
Enumerate crash cuts independently under the declared model and compare logical obligations.
Write number 37 in Linux need not correspond to write number 37 in Asterinas.
Begin with bounded short workloads and systematic cuts around sync/commit boundaries;
expand to seeded stress after the negative controls establish sensitivity.
Record explored schedules and bounds; do not call a sampled campaign exhaustive.

## 6. Rules for implementing and importing subsystems

For every work package:

1. Inventory existing implementation, documentation, tests, and known exclusions.
2. Define a finite contract and its supported/unsupported surface before changing code.
3. Pin the upstream oracle/test source and prove the test setup works on that oracle.
4. Capture an Asterinas failure or missing capability with a minimized reproducer.
5. Design the native Rust interfaces, ownership, lock order, failure/rollback behavior,
   resource bounds, and feature-discovery rules.
6. Implement the smallest complete vertical behavior, including negative cases.
7. Validate pure/kernel tests, paired ABI tests, fault/concurrency cases,
   and the relevant application scenario.
8. Update SCML/compatibility docs, regression registry, profile manifest,
   and status with the actual evidence and remaining limitations.

Keep kernel code safe Rust and respect the acyclic crate layers.
New unsafe primitives require an OSTD-level design and focused safety review;
do not weaken a boundary to fit a borrowed implementation.
Separate pure format/validation/state-machine code from device and scheduling effects where practical.
Use explicit transaction and lifetime types when they prevent illegal operations.
Do not introduce a generic abstraction solely for a hypothetical later subsystem.

### 6.1 Provenance and reuse

Check existing Asterinas code, upstream changes, and independently maintained Rust components
before implementing an algorithm from scratch.
Timebox candidate evaluation and use the same tests for adopted and original code.
Evaluate `no_std`/allocation needs, safe-Rust boundaries, concurrency assumptions,
feature limits, error semantics, maintenance history, and provenance.
A crate README or a successful mount is not evidence of filesystem reliability.

Record exact sources, licenses, notices, and modifications for copied or adapted material.
Linux source and test files have their own licensing requirements;
translation into Rust does not erase provenance.
Do not mechanically translate GPL implementation code and place an MPL header on it.
Prefer separately built upstream oracle/test inputs and independently designed compatible behavior;
resolve the per-file reuse conditions before importing code.
If a proposed import cannot meet repository policy, continue with an alternative implementation.
See [repository licensing](.licenserc.yaml) and
[Linux licensing rules](https://docs.kernel.org/process/license-rules.html).

### 6.2 Regression registry

Each regression record links the upstream issue/fix/test revision,
affected contract, applicability rationale, minimal witness,
native regression ID, and current evidence.
Classify records as applicable now, future selected feature,
Linux-internal-only, or excluded with a reason.
Test a pre-fix and post-fix Linux revision when practical to establish sensitivity;
otherwise record exactly what independent evidence validates the reproducer.

Start with verified merged ext4/JBD2 fixes and existing blocked cases.
Do not claim to have imported a dated patch series, test count, or bug corpus
until its exact source and applicability have been recorded.
Keep a process for reviewing new relevant upstream fixes,
without automatically broadening the profile or installing a recurring task as part of this plan.

## 7. Work packages and exit evidence

All packages below begin **planned**.
Dependencies are logical gates, not a demand to serialize unrelated read-only investigation.
One owner should control shared APIs and integration; independent implementation work can use isolated branches.

### H0 — Inventory and reproducible inputs

Inventory dispatch entries, SCML flags, implementation stubs, unsupported-success paths,
existing tests, blocked cases, compiled-out assertions, and actual CI jobs.
Reconcile documentation disagreements without promoting unexecuted support claims.
Resolve the reference Linux and tool/suite pins, configuration, build environment,
artifact identities, host requirements, budgets, and profile schema.

**Exit:** a reproducible inventory and lock manifest;
every selected obligation has a source and status;
missing runtime evidence is explicit;
the next pilot can be executed from a fresh checkout without sibling repositories.

### H1 — Runner and parser credibility

Implement the minimal runner, run-bound result protocol, suite parsers,
subtest accounting, cleanup, and evidence bundles.
Run a small deterministic Linux-to-Linux corpus in fresh equivalent guests.
Exercise the H1 protocol, accounting, parser, supervisor, and comparator controls in section 5.5.
Record the remaining live-device and persistence controls as explicit later obligations.
Keep existing suite wrappers usable while introducing the stricter qualification path.

**Depends on:** H0.
**Exit:** correct reference self-comparison, all H1 controls detected,
complete result accounting, reliable cancellation, and a replayable failure bundle.

### H2 — Ext2 and one non-filesystem pilot

Qualify a fixed ext2 corpus on both kernels:
create/read/write, sparse/truncate/extend zeroing, links/rename,
permissions, file/directory synchronization, ENOSPC/EIO,
clean remount, Linux readback, and offline structural validation.
Add one compact eventfd/epoll or pipe/FD-lifetime corpus
to prove the same runner supports another subsystem.
First preserve the full failing baseline; then fix the required pilot contracts.
Capturing that paired diagnostic baseline unlocks S0;
complete H2's final storage qualification together with S0 at G1.
This permits fixing discovered defects without treating the failing baseline as a pass.

**Depends on:** H1 and the minimum H3 device setup.
**Exit:** required pilot cases pass on both kernels with independent validation,
and deliberate content/readiness defects are detected.
Complete the persistence-sensitivity control in S0 before claiming G1.
No failed case disappears by changing the selection.

### H3 — Firecracker and QEMU adapters

Extend the Firecracker adapter beyond its boot marker:
generated test/scratch disks, explicit safe cache settings,
network fixtures, guest workload startup, result delivery,
device identity, shutdown, and host timeout supervision.
Keep existing QEMU device configuration as a second adapter.
Do not assume `/dev/vdd`/`vde` from the current xfstests QEMU layout applies to Firecracker.
Run Linux and Asterinas on the same backend where possible.

**Depends on:** H0/H1; implement the minimal disk adapter before H2.
**Exit:** the same pilot manifests run on the primary target;
backend capability differences are explicit;
storage/network presence and cleanup are verified, not inferred from successful boot.

### H4 — Corpus integration and diagnostic tooling

Connect the existing conformance suites incrementally,
retaining upstream case IDs, patches, prerequisites, and exact selection counts.
Add regression-registry and compatibility-report generation.
Collect native kernel counters and bounded tracing for syscalls,
faults, scheduling, waits, allocation, block I/O, and network events as needed for failures.
Reuse OSDK profiling and existing logging infrastructure.
Instrumentation must work in Asterinas; Linux perf/eBPF is not a prerequisite for diagnosing it.

**Depends on:** H2.
**Exit:** at least two real subsystems share the manifest/report path,
new failures can be minimized and replayed,
and enabling diagnostics does not become an undocumented requirement for passing.

### S0 — Block, VFS, and writeback foundations

Audit the complete durable path from syscall through page cache,
filesystem metadata, BIO completion, virtio negotiation, VMM, and backing storage.
Retain asynchronous writeback failures so appropriate later synchronization calls report them.
Specify per-inode/open-file-description error observation and test independent descriptors.
Handle repeated errors, failed flushes, device loss, queue limits,
partial I/O, and allocation failure without silent success or panic.

Remove hidden assumptions that large requests always fit the virtqueue or contiguous allocation.
Test split request completion and backpressure.
Document VFS/page-cache lock ordering and mapping/truncate/writeback interactions.
Extend the memory disk into a bounded traceable durable/volatile model,
with independent validation of the model itself.

**Depends on:** H2's captured diagnostic baseline and H3's minimal storage adapter.
Complete H2 and S0 together before claiming G1.
**Exit:** write and flush failures reach the relevant callers;
successful synchronization has the declared storage meaning;
the pilot detects dropped barriers;
existing ext2/exfat/tmpfs/overlayfs/virtiofs behaviors affected by shared changes are preserved.

### S1 — Ext4 format policy and clean reader

Design a native ext4 module and separate filesystem registration.
Reuse sound ext-family primitives where justified;
do not turn ext2 into nominal ext4 by relaxing feature masks.
Keep ext2 support separately testable.

The first writable target, `ext4-ordered-v1`, is deliberately finite:

| Property | Target contract |
| --- | --- |
| Geometry | 4 KiB filesystem blocks and 256-byte inodes; checked 64-bit metadata addressing. |
| Data mapping | Extents, holes, unwritten extents, valid tree growth/depth, large files and sparse ranges. |
| Metadata | 64-bit group descriptors, metadata checksums, indexed directories, extended inode fields. |
| Related features | Explicit handling for selected baseline bits including filetype, ext_attr, sparse_super, large_file, huge_file, dir_nlink, extra_isize, flex_bg, and initialization flags permitted by the format. |
| Journal | Internal JBD2 journal, one explicitly enumerated checksum/feature combination, `data=ordered`. |
| Permissions | POSIX ownership/mode semantics, xattrs, access/default ACLs, and supported file capabilities. |
| Orphans | Traditional orphan-chain recovery; `orphan_file` disabled until its own gate. |
| Unsupported features | Enumerated mount policy; safe refusal, or explicitly supported read-only behavior that cannot accidentally write/replay. |

Before implementing mutations, materialize the profile with pinned e2fsprogs,
an explicit mkfs recipe/configuration, and inspected resulting feature masks.
Include prerequisites implied by chosen features;
do not rely on evolving `mke2fs` defaults.
This profile does not claim support for every volume produced by default `mkfs.ext4`.

Validate superblocks, group descriptors, inode sizes, addresses, checksums,
allocation geometry, extent ordering/overlap/bounds,
directory records/HTree bounds, xattrs, and symlinks against Linux-created fixtures.
Use multi-group, nearly full, fragmented, sparse, large-address, and malformed images.
Bound recursion, memory, and work on corrupt input.
Preserve unknown fields and flags according to the documented policy;
do not clear them simply to produce an accepted image.

The clean-reader milestone accepts only images whose recovery state it understands.
Refuse recovery-needed images until S2 exists.
Linux read-only mounts may replay and write;
`ro,noload` is not evidence that an unrecovered image is consistent.
See [ext4 mount semantics](https://docs.kernel.org/admin-guide/ext4.html),
[superblock format](https://docs.kernel.org/filesystems/ext4/super.html),
and [inode format](https://docs.kernel.org/filesystems/ext4/inodes.html).

**Depends on:** H2 and the format-facing parts of S0.
**Exit:** clean read-only interoperability for the declared profile,
feature-policy tests, malformed-input/resource tests,
and no accidental writable fallback.

### S2 — JBD2 recovery

Implement journal parsing and recovery as a bounded state machine with explicit endian conversion,
framing, transaction sequence handling, checksums, escaped blocks,
revoke rules, and committed-versus-incomplete transaction decisions.
Reject unsupported journal features before replay.
Test transaction-ID wrap, log wrap, reused blocks, truncated/corrupt records,
recovery interrupted by I/O failure, and repeated replay.
Record an error state without marking an unsuccessfully recovered filesystem clean.

Retain each crash image unchanged.
Create independent clones for candidate recovery, Linux recovery,
and optional e2fsprogs journal-only diagnosis.
After successful kernel recovery and clean unmount,
run offline `e2fsck -fn` and semantic validation.
At this stage use replay fixtures without pending orphan cleanup.
Journal replay alone is not complete recovery of an image with orphaned inodes;
S3 adds orphan-chain cleanup and transactional orphan updates,
and S4 applies cross-recovery and clean-fsck gates to the full profile.
A general fsck repair must not turn failed kernel recovery into a pass.
Preserve validator exit codes and diagnostics;
“errors corrected” is not clean initial validation.

**Depends on:** S1 and S0's persistence model.
**Exit:** replay obeys the declared JBD2 contract,
is idempotent where required, survives interrupted recovery,
and produces independently validated state for the replay-only fixture contract without broad repair.
Reference: [JBD2 format](https://docs.kernel.org/filesystems/ext4/journal.html)
and [e2fsck manual source](https://github.com/tytso/e2fsprogs/blob/master/e2fsck/e2fsck.8.in).

### S3 — Transactional ext4 writer

Define transaction handles/credits and ownership of dirty metadata before adding mutation paths.
Cover data-before-metadata-commit ordering for newly exposed data,
journal persistence, checkpointing, log-space exhaustion,
commit/replay serialization, abort handling, and the declared error-to-read-only policy.
Never silently fall back to unjournaled writes.
An eager allocator is acceptable initially;
Linux delayed-allocation or extent-cache internals are not mandatory architecture.

Implement allocation/free, inode creation/deletion,
extent insert/split/merge/root growth/collapse,
unwritten conversion, sparse reads, truncate/extend zeroing,
directory creation/index growth/collisions, links/rename,
open-unlink and interrupted truncate/extension orphan handling,
including recovery-side orphan cleanup and transactional orphan-chain updates,
xattrs/ACLs and capability semantics.
Apply shared page-cache/mmap and direct-I/O coherency rules to supported paths.
Unsupported modes must be rejected honestly, without reporting a stronger capability.

Test ENOSPC at both data and metadata allocation boundaries,
quota-independent resource exhaustion, short writes, copy faults,
allocation failure, journal-full backpressure, concurrent sync,
and rollback/error behavior.
No partially implemented transaction path is exposed as production writable ext4.

**Depends on:** S0, S1, S2.
**Exit:** the full `ext4-ordered-v1` operation contract passes,
including error paths and clean Linux cross-mount readback;
no supported feature bypasses transactional accounting.

### S4 — Storage qualification and application durability

Add ext4 through the existing
[xfstests template](test/initramfs/src/conformance/xfstests/template)
and include a fixed applicable set of generic/ext4 and pjdfstest cases.
Retain tests for unsupported features as separately accounted applicability records.
Classify device-mapper, debugfs, kernel-internal, or injection-dependent upstream cases
before running them; preserve their relevant invariant in a native test where appropriate.

Exercise Linux-created images on Asterinas and Asterinas-mutated images on Linux,
including journals produced by each implementation and recovered by the other.
Test application state, not just filesystem structure:

- SQLite rollback-journal and WAL transactions with declared durability settings.
- Atomic file publication: write, sync file, rename, sync parent directory.
- Replacement and cross-directory rename with the required directories synchronized.
- Open-unlink, link counts, concurrent writers, mmap/truncate, full volumes,
  dirty shutdown, corrupted metadata, and repeated failed recovery.

Distinguish acknowledged operations whose durability is required
from unacknowledged work for which more than one recovered state is legitimate.
Journaled metadata alone does not guarantee arbitrary unsynchronized file data.
Run systematic bounded crash cuts and seeded long workloads,
with missing-sync negative controls and independent structural/semantic validators.

**Depends on:** S3 and required C0/M0 prerequisites.
**Exit:** G2 below, with a published feature/mount/storage-model matrix,
all required cases passing, no unexplained corruptions,
and retained replayable evidence.

### C0 — Processes, threads, signals, and readiness

Audit existing clone/clone3/fork/vfork/exec/wait behavior,
thread-group exit, PID 1/reparenting, process groups/sessions,
pidfds, descriptor inheritance/CLOEXEC, and supervision cancellation.
Validate struct-size/version handling and requested flags;
warning and ignoring a requested security/lifecycle effect is not sufficient.

Qualify shared/private/robust futex behavior, requeue/wakeup operations required by libc,
thread death, timeout clocks, signal interruption/restart,
epoll/poll/select edge/level/oneshot semantics,
eventfd/signalfd/timerfd, pipes, and Unix FD passing.
Use existing gVisor/LTP/kselftest coverage and minimized native probes.
Recheck old blocklist entries rather than assuming all still fail.
Priority-inheritance or newer futex APIs need a separate explicit admission if the selected runtime requires them.

**Depends on:** H2/H4; may fix concrete ext4 prerequisites earlier.
**Exit:** pinned multithreaded musl/glibc workloads and supervisor/PTY probes
survive cancellation, signals, fork/exec, and repeated lifecycle churn
without hangs, lost wakeups, descriptor leaks, or changed assertions.

### C1 — Memory mappings and useful missing ABI

Qualify anonymous/file/shared/private mappings, COW/fork,
protection changes, address reservations, MAP_FIXED_NOREPLACE,
truncate/EOF SIGBUS behavior, shared dirty pages,
memfd seals and executable mappings, and copy-to/from-user failure boundaries.
Preserve file mapping correctness across writeback, invalidation, and unmount.

Prioritize `mincore`, bounded `mlock/munlock` accounting,
and `membarrier` when selected runtime/diagnostic contracts require them.
Check permissions and limits before allowing pinned memory.
These need exact semantics and tests, not successful no-op implementations.
Treat rseq, huge pages, userfaultfd and other deferred facilities separately.

**Depends on:** C0 and S0 for file-backed paths.
**Exit:** required mapping/protection/visibility cases pass under concurrency and allocation failure,
and pinned application runtimes work without unsafe feature disabling.

### C2 — VFS, mounts, locks, and file notifications

Qualify path resolution and descriptor-relative operations,
openat2/O_PATH/O_TMPFILE where selected, symlinks, bind mounts,
renameat2 flags, stat/statx metadata, directory iteration,
mount namespaces, and the modern mount API already present in the tree.
Exercise POSIX/OFD file locks and flock under fork, dup, close, exec,
interruption, and competing processes; databases require effective locking.

Qualify inotify watch lifetime, rename relationships, queue overflow,
unlink/unmount behavior, and readiness under concurrent mutation.
Use file-watcher, log-following, build-tree, and database workloads,
with persistent state and permission checks on both ext2 and the qualified ext4 profile.
Modern mount interfaces and notification mechanisms are audited per supported operation;
fanotify and every new mount feature are not implicit requirements.

**Depends on:** H4, C0, and S0; ext4-specific completion follows S3.
**Exit:** selected mount/metadata/locking/notification contracts pass,
including concurrency and lifecycle failures,
without application-specific filesystem workarounds.

### M0 — Memory pressure and bounded kernel resource use

Implement pressure-driven clean-page reclaim, bounded dirty-page writeback/throttling,
allocation-failure propagation, and an explicit OOM policy.
Resolve lock-order and recursion risks between allocation, reclaim, filesystem operations,
journal reservation, and device completion before enabling reclaim broadly.
Avoid requiring large physically contiguous allocations for ordinary pipes or growing kernel buffers.
Audit long-lived caches, epoll registrations, sockets, dentries, tasks, and page ownership for leaks.

Use controlled single-vCPU and SMP memory budgets,
mixed anonymous/file-backed load, sustained filesystem traffic,
fragmentation, fork/thread churn, and intentionally failing allocations.
Test that an independent supervisor/control path remains responsive,
and that surviving applications retain required persistent state.
No-swap is the initial profile; swap is not required to make memory use bounded.

**Depends on:** C0/C1 and S0's locking/error foundations.
**Exit:** bounded workloads converge to stable resource use,
exhaustion has the documented failure/termination behavior,
the kernel remains responsive, and no successful durability acknowledgment is invalidated.

### M1 — Scheduler and cgroup v2 enforcement

Implement actual CPU weight/quota enforcement and statistics,
hierarchical memory charging/current/high/max/events with reclaim/OOM behavior,
and verify existing hierarchical PID charging.
Add the selected single-node cpuset behavior, freezer and kill semantics
needed by the confined-service profile, with explicit unsupported files/values elsewhere.
Cover migration, fork/exit rollback, ancestor limits, delegation,
controller enable/disable, and task lifetime races.

Test effective limits with competing workloads and known allocations,
not only attribute writes and readback.
Define tolerances for CPU-share measurements before measuring;
verify hierarchy and bounded throttling without requiring Linux's scheduler internals.
Provide truthful RSS/usage/pressure information for supported interfaces.
If PSI is exposed, qualify its semantics; never fabricate zero pressure to satisfy consumers.

**Depends on:** M0 and C0; permission/delegation checks coordinate with Q0.
**Exit:** unprivileged workloads cannot escape selected limits,
resource exhaustion is contained, and observed accounting/enforcement matches the declared contract.
Reference: [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).

### N0 — Network data plane and socket semantics

Preserve the existing Rust network stack and regression corpus.
Qualify TCP connection/shutdown/reset/half-close/retransmission,
backpressure, buffer limits, errors, timeout/signal interaction,
UDP datagrams/truncation/error queues, and Unix stream/datagram/seqpacket behavior.
Include ancillary data, credentials, SCM_RIGHTS lifetime and FD limits,
poll readiness, cancellation, and slow/disappearing peers.
Add `recvmmsg` and missing batching behavior when required by the selected service profile.

Use controlled Linux peers, packet capture, deterministic impairment where feasible,
and bounded packetdrill-style contracts.
Compare required wire behavior and application outcomes,
not an exact congestion window or identical packet schedule.
Fuzz bounded parsers and malformed socket/netlink inputs,
including resource exhaustion and cleanup.

**Depends on:** H3/H4 and C0; resource-stress exit depends on M0.
**Exit:** pinned DNS/HTTP/TLS-over-TCP consumers and Unix IPC scenarios
retain correct behavior through packet loss, delay, reconnect, cancellation, and pressure.
DNS and TLS implementations remain userspace consumers, not new kernel subsystems.

### N1 — Network configuration, time, and VM lifecycle

Qualify existing IPv4 and IPv6 code against complete selected workflows:
address/route/neighbor state, loopback, dual-stack sockets,
IPv6 discovery and lifetimes, link transitions, MTU/error behavior,
and netlink requests, dumps, notifications, acknowledgments, and compatibility/error precedence.
Keep the initial goal endpoint networking, not a router/firewall distribution.

Qualify existing real/monotonic/boottime clocks, clock adjustment,
absolute/relative timers, vDSO consistency, permission checks,
and timer cancellation on clock steps.
Use a pinned time-service workload and controlled clock/network disruptions.
Record VM pause/resume behavior without making host suspend or guest hibernation part of scope.

Include vsock/console/entropy device lifecycles where selected by `vm-core`.
Validate early-boot and failure behavior of random-number interfaces;
do not accept deterministic test randomness in release builds.

**Depends on:** N0, C0, H3.
**Exit:** service/network/time state recovers from declared disruptions,
diagnostics report real state, and selected workflows work as root and unprivileged users.

### Q0 — Credentials and confinement

First qualify current IDs/groups, capabilities, setuid/setgid and file capabilities,
`no_new_privs`, exec transitions, ptrace access checks,
mount permissions, procfs visibility, openat2 resolution, and inherited/passed FDs.
Test both permission denial and permitted operation;
a missing device or unrelated error does not prove access was denied correctly.

Implement the Landlock userspace ABI as a finite versioned contract,
with **ABI 6 as the initial target**, not a claim to follow every newer ABI automatically.
Include all semantics required to advertise that version:
filesystem restrictions and refer/truncate/device-ioctl behavior,
TCP bind/connect restrictions, abstract-Unix/signal scoping,
ruleset lifetime, layering, inheritance, and interaction with existing FDs/mounts.
Use the matching upstream selftests and adversarial rename/link/mount/FD scenarios.
Do not implement restrictions as path-string prefix checks.
Advertise only the ABI version actually qualified.
For ABI 6, restriction applies to the installing thread and its future descendants,
not automatically to already-existing sibling threads.
Qualify installation before worker creation or explicit per-thread enforcement;
seccomp TSYNC does not supply Landlock thread synchronization.
Newer requested rights must be rejected at consumer admission rather than silently downgraded.

Implement seccomp's bounded classic-BPF filtering contract:
validation/interpreter bounds, syscall architecture/argument handling,
filter stacking and action precedence, process/thread inheritance,
TSYNC, `no_new_privs`, signal/error/kill behavior,
and the explicitly supported action-discovery interface.
Unsupported actions/flags follow their documented failure behavior;
they must not become an allow-all path.
Coordinate ptrace interactions with the chosen profile.
User notification and a general eBPF subsystem remain deferred.

**Depends on:** C0/C1, S3 for persistent permission/xattr cases, and N0 for network restrictions.
**Exit:** selected unmodified sandbox consumers enforce their requested policy,
unsupported policy fails closed at the consumer boundary,
and denial/allowance/inheritance/escape-regression tests pass.
References: [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
and [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html).

### Q1 — Namespaces and restricted process trees

Qualify current mount/UTS/IPC/cgroup namespace behavior,
mount propagation, pivot/chroot boundaries, ownership, and procfs views.
Implement PID/user namespace contracts with UID/GID maps,
supplementary-group rules, namespace-scoped capabilities,
nested visibility, namespace-init exit/reaping, signals, pidfds, and resource accounting.
Implement network namespaces only after separating ownership of network state,
then test real address/route/socket visibility and teardown isolation.
Creating a namespace handle without isolation does not count.

Use small adversarial standalone workloads and selected upstream namespace tests.
Do not require a full container engine to begin proving kernel isolation.
Do not weaken sandbox or credential flags to make an application start.

**Depends on:** Q0, M1, C0, and N0/N1 for the network namespace part.
**Exit:** confined process trees cannot observe or modify resources outside their declared boundaries,
limits remain enforced across namespace operations,
and teardown does not leak tasks, network state, mounts, or references.

### D0 — Diagnostics, device discovery, TTY, and input

Harden existing devtmpfs/sysfs/uevent integration:
creation/removal ordering, stable identities, permissions,
coldplug/reconciliation, lost-notification handling, and daemon restart.
Qualify `/proc`, `/sys`, `/dev/kmsg`, resource statistics,
and supported sysctl/configuration interfaces used by standalone administration tools.
Unsupported functionality should be distinguishable from a legitimate zero measurement.

Qualify PTY/TTY/session/job-control semantics, window changes,
hangup, signal delivery, canonical/raw operation, and relevant terminal permissions.
For evdev, implement real key/button state, packet boundaries,
SYN_DROPPED recovery, nonblocking readiness, grab/revoke,
disconnect HUP/error behavior, and repeated device/session lifecycle.
Use existing probes, pinned libevdev/libinput cases,
and deterministic virtual input with independently observed output.

**Depends on:** C0/C1, H3's QEMU adapter, and Q0's credential foundations.
**Exit:** device consumers recover from loss/restart,
terminal sessions behave correctly, and input state/event tests pass without false-ready busy loops.

### D1 — Bounded virtual desktop

Start with the existing simpledrm/GEM/KMS foundation and a named software-rendered compositor.
Qualify dumb-buffer allocation/mapping/lifetime,
DRM master and broker-mediated FD transfer,
event queue read/poll semantics, pageflip completion,
client teardown, and permission denial.
Add atomic modesetting and needed framebuffer/property behavior
only as explicit complete contracts for the chosen virtual display profile.

Introduce virtio-gpu 2D if the selected profile requires a dynamic virtual display device.
Its presence must be established by a driver and runtime evidence,
not a device-ID enum or buildable ioctl definitions.
Keep software rendering as the baseline.
PRIME/dma-buf/fences/render nodes and acceleration have separate admitted contracts
with sharing, synchronization, revocation, and lifetime tests.

Use selected libdrm/IGT tests plus an unmodified compositor and terminal.
Require actual injected input, changed client content,
presentation completion, and independently captured pixels,
then compositor/broker death and device/session recovery.
Distinguish virtual device removal from physical hotplug or suspend.
Firecracker cannot qualify this profile; run it through the explicit QEMU backend.

**Depends on:** D0, C1, M0, Q0; G2 remains the first major delivery.
**Exit:** the named software desktop scenario passes its device/security/lifecycle matrix,
with unsupported graphics capabilities reported accurately.
No claim of general GPU or desktop hardware support follows.

### D2 — Optional virtual audio

Define a small ALSA PCM/control contract and one virtual device,
preferably virtio-snd if the chosen test backend supports it.
Cover stream negotiation, buffer ownership, poll/mmap/read/write semantics,
timestamps, underrun/overrun, cancellation, permission, and device loss.
Use independently recorded/validated audio samples and frame counts;
a successful playback API return alone does not establish delivery.

**Depends on:** D0, C0/C1, M0 and an explicit `virtual-audio` admission.
**Exit:** declared playback/capture and failure contracts pass with bounded memory/latency.
Sound-server, codec, MIDI, and native hardware implementation remain excluded.

### P0 — Performance and selective ABI expansion

Measure boot/readiness, syscall/FD costs, page faults/COW,
allocation/reclaim, scheduler wakeups, block throughput and sync latency,
metadata-heavy workloads, TCP/UDP throughput/latency, and idle resource use.
Prioritize measured bottlenecks rather than duplicating Linux algorithms.
Possible later optimizations include request splitting/batching,
reduced copying, multiqueue, allocator improvements,
selected splice/sendfile paths, and io_uring only if its full chosen lifecycle contract is justified.

Use identical workload/output validation, guest resources, CPU exposure,
cache/warmup conditions, security and durability settings,
and equivalent compiler/build modes.
Keep cold and warm results separate.
Report raw samples, medians and tail latency, memory peak/steady state,
failures, host interference, and uncertainty across repeated trials.
Freeze budgets and thresholds before optimization;
do not select only favorable seeds, discard timeouts,
change fsync/security semantics, or benchmark a smaller workload as an optimization.

**Depends on:** the relevant correctness gate; baseline measurement can begin earlier.
**Exit:** each claimed improvement has reproducible before/after evidence
and no relevant correctness, resource, security, or durability regression.
No universal “within N percent of Linux” claim is made without workload-specific data.

### A0 — AArch64 portability and retained-platform regression

Preserve existing architecture boundaries during implementation.
After x86-64 profile qualification, select and pin a supported AArch64
boot/VMM/device configuration and run the same profile contracts there.
Audit endianness assumptions, structure layout, pointer/integer widths,
memory ordering, page size, atomics, syscall numbering, and vDSO behavior.

**Depends on:** the profile being ported and a real execution host.
**Exit:** independent AArch64 runtime receipts and cross-build checks for retained targets.
An unavailable host is an explicit block, not inferred success from x86-64 or cross-compilation.

## 8. Delivery gates and completion rules

| Gate | Required evidence |
| --- | --- |
| G0 — Credible harness | H0/H1, actual input pins, Linux self-comparison, complete accounting, all H1 negative controls, reproducible artifacts; live-device and persistence controls remain explicit pending obligations. |
| G1 — Existing kernel baseline | H2/H3, ext2 and non-filesystem pilots on the primary target, S0 durability/error controls, current passing regressions preserved. |
| G2 — Durable ext4 | S1–S4, exact feature/mount/backend contract, independent fsck/semantic checks, cross-mount and cross-recovery, bounded crash campaign, database/publication workloads, required pressure/concurrency prerequisites. |
| G3 — Reliable services | C0/C1/C2/M0/N0/N1 and relevant D0 diagnostics; long-lived application scenarios survive declared resource, process, clock, network, and storage disruptions. |
| G4 — Confined services | Q0/Q1/M1; selected policy, namespace, and resource restrictions are demonstrably enforced. |
| G5 — Virtual desktop | D0/D1 with named virtual devices, software rendering, input/presentation evidence, access controls and lifecycle recovery. Audio is separately gated. |
| G6 — Portability/performance | A0 and applicable P0 evidence for each claimed profile/platform/improvement. |

G2 depends only on the C0/M0 behavior needed for its declared workload and resource envelope;
it does not wait for every later service or sandbox feature.
Its profile must state any remaining resource limits honestly.
G3/G4 add stronger long-lived and hostile-workload obligations.
Profile inheritance must be explicit in the generated manifests:
services retains the selected G1/G2 contracts,
confined-services retains those service contracts while adding G4,
and the desktop/audio profiles retain their shared core, storage, and credential requirements.
Passing isolated policy or graphics tests cannot waive failures in inherited required contracts.

For every gate:

- All mandatory cases and assertions execute and pass; exclusions are explicit and stable.
- No known unresolved data-integrity or privilege-isolation defect affects the claimed profile.
- No unexplained panic, hang, lost acknowledgment, resource leak, or validator repair is accepted.
- A Linux reference failure blocks that comparison; it does not waive the candidate result.
- The same checks preserve previously qualified exact case IDs, not merely aggregate counts.
- The checked artifact and configuration are the ones promoted; dirty builds and stale evidence cannot substitute.
- The report states tested bounds and limitations instead of claiming complete Linux or bug-free parity.

### 8.1 CI progression

Start with a small required gate, then add verified slices:

1. Every change: existing lint/host checks, manifest/parser controls, relevant pure tests,
   build checks and the current boot smoke.
2. After G1: required kernel/regression tests and a bounded paired ext2/core ABI suite on KVM.
3. After G2: required ext4 short list, error/durability controls,
   and affected-profile regressions for storage or shared VM changes.
4. Scheduled or explicitly invoked longer runs: broader applicable suites,
   seeded stress/crash exploration, application soak, performance, and device profiles.
5. Release qualification: complete selected profile matrix and retained artifacts,
   independent of whether a small per-change smoke passed.

Record separate statuses for build-only, runtime-tested, reference-compared,
fault-qualified, and application-qualified capability.
Restore useful upstream CI ideas selectively;
do not copy a large matrix and report unavailable runners as success.

## 9. Execution protocol for implementation agents

When assigned to execute this campaign, read Status, the selected profile,
the relevant code/test owners, and repository guidelines.
Start from the smallest ready work package.
Keep investigating and fixing within that scope until its exit evidence is concrete,
then update Status and proceed to the next dependency-ready package.
Scaffolding, a new test manifest, or a passing build is not the end of a subsystem task.

Use coherent commits: reproducer/contract, implementation, and evidence/docs as appropriate.
Separate broad refactoring from behavior changes.
Preserve other work in the repository and use isolated worktrees/branches for parallel changes.
Assign an independent reviewer to storage transaction logic,
permission boundaries, shared lifetime/locking changes, and harness expectation changes.
One integration owner resolves shared-interface conflicts and runs the combined gate.

Do not improve reported results by deleting tests,
silencing failures, accepting empty runs, weakening assertions,
automatically broadening allowed outcomes, increasing deadlines after observing failure,
disabling requested application security, or changing oracle settings without disclosure.
Fix setup failures as setup failures, and kernel failures in the kernel.
An intentional policy change must be explicit and reviewed with its consequences.

If execution is blocked by a missing host/device/input or an unresolved design boundary,
record the exact blocker, complete independent useful work,
and leave a replayable next action.
Do not invent results or mark the package complete.
This document does not authorize unrelated repository edits, upstream messages,
new deployment services, or implementation of excluded features.

## 10. Primary references and local starting points

These links are discovery references.
Implementation must lock the exact source revision and license of each adopted test/input;
the links do not imply the latest version has already been evaluated.

| Topic | Primary sources / local entry points |
| --- | --- |
| Kernel organization and development | [AGENTS.md](AGENTS.md), [guidelines](book/src/to-contribute/coding-guidelines/README.md), [Makefile](Makefile). |
| Existing test payloads | [initramfs README](test/initramfs/README.md), [conformance dispatch](test/initramfs/src/conformance/run_conformance_test.sh), [regressions](test/initramfs/src/regression). |
| Existing filesystem integration | [xfstests README](test/initramfs/src/conformance/xfstests/README.md), [package](test/initramfs/nix/conformance/xfstests.nix), [pjdfstest README](test/initramfs/src/conformance/pjdfstest/README.md). |
| Linux tests | [kselftest](https://docs.kernel.org/dev-tools/kselftest.html), [KUnit](https://docs.kernel.org/dev-tools/kunit/index.html), [LTP](https://github.com/linux-test-project/ltp), [gVisor syscall tests](https://github.com/google/gvisor/tree/master/test/syscalls/linux). |
| Filesystem tests and tools | [xfstests](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/), [xfstests-bld](https://github.com/tytso/xfstests-bld), [e2fsprogs](https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/). |
| Ext4 specification | [format index](https://docs.kernel.org/filesystems/ext4/index.html), [JBD2](https://docs.kernel.org/filesystems/ext4/journal.html), [orphan handling](https://docs.kernel.org/filesystems/ext4/orphan.html). |
| Crash methodology | [dm-log-writes](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html), [replay tool](https://github.com/josefbacik/log-writes), [CrashMonkey](https://github.com/utsaslab/crashmonkey). |
| Virtual storage contract | [Firecracker block caching](https://github.com/firecracker-microvm/firecracker/blob/main/docs/api_requests/block-caching.md), [Virtio 1.2](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html). |
| Security and resource ABI | [Landlock](https://docs.kernel.org/userspace-api/landlock.html), [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html), [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html). |
| Fuzzing | [syzkaller OS integration](https://github.com/google/syzkaller/blob/master/docs/adding_new_os_support.md); start with minimized supported reproducers. |
| Device ABI | [DRM userspace API](https://docs.kernel.org/gpu/drm-uapi.html), [input protocol](https://docs.kernel.org/input/event-codes.html), [existing DRM regressions](test/initramfs/src/regression/device/drm). |
| Provenance | [repository license policy](.licenserc.yaml), [Linux licensing rules](https://docs.kernel.org/process/license-rules.html). |
