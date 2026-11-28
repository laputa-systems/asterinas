# Compatibility inventory (generated)

Regenerate with `python3 test/qualification/inventory/inventory.py generate`.
Verify with `python3 test/qualification/inventory/inventory.py check`.

Statuses are shallow handler-resolution evidence, not Linux-compatibility claims; see `metadata.status_semantics` in inventory.json.

## Syscall dispatch

- dispatch rows: 474
- dispatched syscalls: 262
- implemented: 256
- partial: 5
- stub: 1
- unresolvable: 0
- divergent-handler syscalls: 0

### SCML coverage

- fully covered: 164
- constrained: 84
- undocumented: 14

### Stub syscalls

- `fadvise64` — kernel/core/src/syscall/fadvise64.rs:20

### Partial syscalls

- `clone` — kernel/core/src/syscall/clone.rs:16
- `clone3` — kernel/core/src/syscall/clone.rs:32
- `memfd_create` — kernel/core/src/syscall/memfd_create.rs:15
- `personality` — kernel/core/src/syscall/personality.rs:6
- `sendmmsg` — kernel/core/src/syscall/sendmmsg.rs:13

## SCML rules

- invocation rows: 327
- undispatched rule names: 2

## Unsupported-success paths

- recorded sites: 111

- `kernel/comps/i8042/src/controller.rs:267` (comment): before the acknowledgment is ignored.
- `kernel/core/comps/cmdline/src/dispatch.rs:158` (comment): Unrecognized module arguments are ignored.
- `kernel/core/comps/cmdline/src/early.rs:44` (comment): Other tokens are ignored. When `loglevel` is absent, the default is `8`
- `kernel/core/comps/cmdline/src/early.rs:77` (comment): Only early-only keys are consumed here; other tokens are ignored.
- `kernel/core/comps/cmdline/src/unimplemented.rs:39` (warn): ostd::warn!("kernel parameter '{}' is not yet implemented", name);
- `kernel/core/comps/device/src/common/attr.rs:269` (comment): Names that are absent are ignored.
- `kernel/core/comps/framebuffer/src/font.rs:75` (comment): rows in the bitmap will be ignored.
- `kernel/core/comps/nvme/src/device/block_device.rs:473` (warn): warn!( "Ignore unexpected completion: CID {} on QID {} has no submitted request", cid, IO_QID );
- `kernel/core/comps/pci/src/arch/loongarch/mod.rs:85` (warn): warn!( "node with a non-zero bus start `{}` is not supported yet", prop.value[3] );
- `kernel/core/comps/pci/src/arch/riscv/mod.rs:81` (warn): warn!( "node with a non-zero bus start `{}` is not supported yet", prop.value[3] );
- `kernel/core/comps/pci/src/capability/mod.rs:118` (warn): ostd::warn!( "superfluous MSI-X Capability structures at {:?} are ignored", dev.location() );
- `kernel/core/comps/systree/src/attr.rs:173` (comment): Removes an attribute by name, freeing its ID. Absent names are ignored.
- `kernel/core/comps/systree/src/utils.rs:427` (comment): In general, the `offset` for attribute write operations is ignored directly.
- `kernel/core/comps/systree/src/utils.rs:577` (comment): In general, the `offset` for attribute write operations is ignored directly.
- `kernel/core/comps/time/src/rtc/cmos.rs:83` (warn): warn!("CMOS RTC reports unexpected status, ignoring this device");
- `kernel/core/comps/virtio/src/device/block/device.rs:290` (warn): ostd::warn!( "Multi-Queue Block IO Queueing Mechanism is not supported yet; using the first queue" );
- `kernel/core/comps/virtio/src/device/block/device.rs:534` (comment): This will be ignored if the device doesn't support the `VIRTIO_BLK_F_FLUSH` feature.
- `kernel/core/comps/virtio/src/device/network/device.rs:67` (warn): warn!( "unsupported device features: {:?}", device_features.difference(supported_features) );
- `kernel/core/comps/virtio/src/device/socket/queue.rs:240` (warn): ostd::warn!("unexpected event length {}, ignoring trailing garbage", len);
- `kernel/core/comps/virtio/src/lib.rs:137` (warn): warn!("Found unimplemented device: {:?}", device_type);
- `kernel/core/comps/virtio/src/transport/mmio/bus/arch/x86.rs:41` (warn): warn!( "Ignore MMIO command-line device at {:#x} because its range overflows", device.base() );
- `kernel/core/comps/virtio/src/transport/mmio/bus/arch/x86.rs:49` (warn): warn!( "Ignore MMIO command-line device at {:#x} due to an error ({:?})", device.base(), err, );
- `kernel/core/comps/virtio/src/transport/mmio/device.rs:306` (warn): warn!( "{:?}: `single_interrupt` ignored: no support for virtio-mmio devices", self.device_type );
- `kernel/core/comps/virtio/src/transport/pci/device.rs:227` (warn): warn!( "{:?}: `single_interrupt` ignored: no more IRQ lines available", self.device_type );
- `kernel/core/comps/virtio/src/transport/pci/legacy.rs:286` (warn): warn!( "{:?}: `single_interrupt` ignored: no more IRQ lines available", self.device_type );
- `kernel/core/src/arch/x86/cpu.rs:468` (comment): - If the L3 cache is present, it will be ignored on AMD CPUs [1] but it will be reported as
- `kernel/core/src/arch/x86/ptrace.rs:117` (comment): `orig_rax` is ignored. Callers should separately assign this
- `kernel/core/src/device/tty/line_discipline.rs:55` (comment): If the line is full, the character will be ignored, but other actions such as echoing
- `kernel/core/src/device/tty/line_discipline.rs:203` (warn): warn!("non-zero VTIME is not supported");
- `kernel/core/src/device/tty/vt/keyboard/handler.rs:154` (warn): ostd::warn!("Alt+Numpad input is not implemented yet");
- `kernel/core/src/device/tty/vt/keyboard/handler.rs:405` (warn): ostd::warn!("VT keyboard action {:?} is not implemented yet", handler);
- `kernel/core/src/device/tty/vt/keyboard/handler.rs:437` (warn): ostd::warn!( "Virtual terminal keyboard handler received unsupported event: {:?}", event );
- `kernel/core/src/events/epoll/file.rs:259` (warn): warn!("{:?} contains unsupported flags", flags);
- `kernel/core/src/fs/file/file_handle.rs:81` (comment): If the file is append-only, the `offset` will be ignored.
- `kernel/core/src/fs/file/file_handle.rs:209` (comment): `O_ASYNC` is ignored if it is not supported. An attempt to enable
- `kernel/core/src/fs/file/inode_handle.rs:416` (comment): If the file has the `O_APPEND` flag, the offset is ignored.
- `kernel/core/src/fs/file/inode_handle.rs:633` (comment): the offset in the `seek()` operation will be ignored.
- `kernel/core/src/fs/fs_impls/cgroupfs/controller/cpu.rs:232` (todo): TODO: Enforce cgroup CPU weight for scheduling and remove this warning.
- `kernel/core/src/fs/fs_impls/cgroupfs/controller/cpu.rs:233` (warn): warn!( "`cpu.weight` is accepted but not enforced yet; weight = {}", weight );
- `kernel/core/src/fs/fs_impls/cgroupfs/controller/cpu.rs:290` (todo): TODO: Enforce CPU bandwidth throttling and remove this warning.
- `kernel/core/src/fs/fs_impls/cgroupfs/controller/cpu.rs:291` (warn): warn!( "`cpu.max` is accepted but not enforced yet; quota = {}, period = {:?}", quota_usec, period_usec );
- `kernel/core/src/fs/fs_impls/cgroupfs/controller/pids.rs:154` (comment): where `pids.max` is not enforced per cgroupv2 semantics.
- `kernel/core/src/fs/fs_impls/ext2/impl_for_vfs/fs.rs:78` (warn): warn!("ext2-specific handling for filesystem flags is not implemented");
- `kernel/core/src/fs/fs_impls/overlayfs/fs/mount/options.rs:406` (warn): warn!( "`fsync=volatile`: not implemented; durability follows the underlying filesystem" );
- `kernel/core/src/fs/fs_impls/virtiofs/inode/metadata.rs:28` (comment): whether the reply is ignored or whether selected fields may still be
- `kernel/core/src/fs/vfs/fs_apis/file_system.rs:56` (warn): warn!("setting file system flags is not implemented");
- `kernel/core/src/fs/vfs/path/resolver.rs:125` (comment): Only the [`AT_EMPTY_PATH`] bit is inspected; the rest are ignored.
- `kernel/core/src/ipc/ipc_ns.rs:202` (warn): warn!("Semaphore doesn't support permission check now");
- `kernel/core/src/ipc/semaphore/system_v/sem.rs:200` (warn): warn!("Semaphore operation doesn't support permission check now");
- `kernel/core/src/net/iface/config.rs:233` (comment): instead of being ignored, and flags that user space cannot change are ignored as in Linux.
- `kernel/core/src/net/socket/ip/datagram/mod.rs:550` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/ip/datagram/mod.rs:575` (warn): warn!("sending control message is not supported");
- `kernel/core/src/net/socket/ip/datagram/mod.rs:588` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/ip/stream/mod.rs:617` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/ip/stream/mod.rs:630` (warn): warn!("sending control message is not supported");
- `kernel/core/src/net/socket/ip/stream/mod.rs:647` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/ip/stream/mod.rs:658` (comment): peer address is ignored for connected socket.
- `kernel/core/src/net/socket/netlink/common/mod.rs:194` (warn): warn!("sending control message is not supported");
- `kernel/core/src/net/socket/netlink/kobject_uevent/bound.rs:50` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/netlink/kobject_uevent/bound.rs:81` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/netlink/route/bound.rs:51` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/netlink/route/bound.rs:108` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/netlink/route/message/attr/link.rs:265` (comment): TODO: Currently, `IS_NET_BYTEORDER_MASK` and `IS_NESTED_MASK` are ignored.
- `kernel/core/src/net/socket/netlink/route/message/attr/link.rs:324` (warn): warn!("link attribute `{:?}` is not supported", class);
- `kernel/core/src/net/socket/packet/mod.rs:221` (warn): warn!("sending control message is not supported");
- `kernel/core/src/net/socket/unix/ctrl_msg.rs:39` (warn): warn!("unsupported control message type in {:?}", header);
- `kernel/core/src/net/socket/unix/ctrl_msg.rs:54` (warn): warn!("unsupported control message type in {:?}", header);
- `kernel/core/src/net/socket/unix/datagram/socket.rs:299` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/unix/datagram/socket.rs:330` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/unix/stream/connected.rs:244` (warn): warn!("setting MSG_TRUNC is not supported");
- `kernel/core/src/net/socket/unix/stream/socket.rs:511` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/unix/stream/socket.rs:557` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/util/message_header.rs:86` (warn): warn!("unsupported control message level in {:?}", header);
- `kernel/core/src/net/socket/util/message_header.rs:100` (warn): warn!("unsupported control message level in {:?}", header);
- `kernel/core/src/net/socket/vsock/stream/mod.rs:338` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/net/socket/vsock/stream/mod.rs:370` (warn): warn!("sending control message is not supported");
- `kernel/core/src/net/socket/vsock/stream/mod.rs:385` (warn): warn!("unsupported flags: {:?}", flags);
- `kernel/core/src/process/clone.rs:286` (warn): warn!("contains unsupported clone flags: {:?}", unsupported_flags);
- `kernel/core/src/process/clone.rs:886` (warn): warn!("CLONE_SYSVSEM is not supported now");
- `kernel/core/src/process/namespace/unshare.rs:46` (warn): warn!("unsharing System V semaphore is not supported");
- `kernel/core/src/process/posix_thread/futex.rs:562` (comment): the bitset in `new_key` is ignored.
- `kernel/core/src/process/posix_thread/futex.rs:588` (comment): the bitset in `new_key` is ignored.
- `kernel/core/src/process/process/terminal.rs:80` (warn): warn!("stealing TTY from another session is not supported");
- `kernel/core/src/process/signal/mod.rs:337` (warn): warn!("Unsupported signal flags: {:?}", flags);
- `kernel/core/src/process/signal/sig_action.rs:78` (comment): Returns whether signals will be ignored.
- `kernel/core/src/process/signal/sig_action.rs:80` (comment): Signals will be ignored because either
- `kernel/core/src/process/signal/sig_queues.rs:207` (comment): Note that signals are ignored but not blocked may be dequeued silently.
- `kernel/core/src/process/wait.rs:43` (warn): warn!( "unsupported wait options are found: {:?}", *self - supported_args );
- `kernel/core/src/security/lsm/modules/mod.rs:16` (comment): ! the mandatory modules in that order. Unknown module names are ignored with a
- `kernel/core/src/security/lsm/modules/mod.rs:17` (comment): ! warning, and duplicate names are ignored after their first selection.
- `kernel/core/src/security/lsm/modules/mod.rs:20` (comment): ! exclusive module is kept, and later exclusive entries are ignored.
- `kernel/core/src/security/lsm/modules/mod.rs:27` (comment): ! If both parameters are specified, `security=` is ignored because `lsm=`
- `kernel/core/src/security/lsm/modules/mod.rs:90` (warn): warn!("`security=` is ignored because `lsm=` is specified");
- `kernel/core/src/security/lsm/modules/mod.rs:127` (warn): warn!( "LSM module `{}` is ignored because `security=` only selects legacy major modules", name );
- `kernel/core/src/security/lsm/modules/mod.rs:158` (warn): warn!("duplicate LSM module `{}` is ignored", name);
- `kernel/core/src/security/lsm/modules/mod.rs:165` (warn): warn!( "LSM module `{}` is ignored because exclusive module `{}` is already enabled", name, exclusive_name );
- `kernel/core/src/syscall/clone.rs:91` (warn): warn!("set_tid is not supported");
- `kernel/core/src/syscall/clone.rs:94` (warn): warn!("cgroup is not supported");
- `kernel/core/src/syscall/fadvise64.rs:40` (warn): warn!("POSIX_FADV_NORMAL is ignored");
- `kernel/core/src/syscall/fadvise64.rs:43` (warn): warn!("POSIX_FADV_RANDOM is ignored");
- `kernel/core/src/syscall/fadvise64.rs:46` (warn): warn!("POSIX_FADV_SEQUENTIAL is ignored");
- `kernel/core/src/syscall/fadvise64.rs:49` (warn): warn!("POSIX_FADV_WILLNEED is ignored");
- `kernel/core/src/syscall/fadvise64.rs:52` (warn): warn!("POSIX_FADV_DONTNEED is ignored");
- `kernel/core/src/syscall/fadvise64.rs:55` (warn): warn!("POSIX_FADV_NOREUSE is ignored");
- `kernel/core/src/syscall/memfd_create.rs:42` (warn): warn!("`MFD_HUGETLB` not supported");
- `kernel/core/src/syscall/personality.rs:16` (warn): warn!("`personality(ADDR_NO_RANDOMIZE)` is accepted, but still does not disable ASLR");
- `kernel/core/src/syscall/rt_sigtimedwait.rs:110` (comment): If the signal is ignored and not blocked, it will be dropped and
- `kernel/core/src/syscall/rt_sigtimedwait.rs:121` (comment): If the signal is ignored and not blocked, the signal will be directly dropped.
- `kernel/core/src/syscall/sendmmsg.rs:28` (warn): warn!("sendmmsg flags {:?} are not supported", flags);
- `kernel/core/src/vm/page_cache/mod.rs:810` (annotation): writeback I/O errors are dropped instead of being recorded, so a later fsync/fdatasync/msync/syncfs reports success for data that was never written; cited in docs/roadmap.md Reference (writeback errors)
- `kernel/libs/aster-ext4/src/extent_edit.rs:247` (comment): blocks are considered; bits beyond the group's block count are ignored.

## Conformance blocklists

- gvisor: 832 blocked cases (788 without a recorded reason)
- kselftest: 91 blocked cases (91 without a recorded reason)
- ltp: 1061 blocked cases (1023 without a recorded reason)
- pjdfstest: 10 blocked cases (8 without a recorded reason)
- xfstests: 136 blocked cases (133 without a recorded reason)

## `__asterinas__` branches

- conditional branches: 52
- compile-flag definitions: 1

- `test/initramfs/src/regression/common/block_device.h:31` #ifdef (positive)
- `test/initramfs/src/regression/device/framebuffer.c:148` #ifdef (positive)
- `test/initramfs/src/regression/device/hwrng.c:171` #ifdef (positive)
- `test/initramfs/src/regression/device/hwrng.c:186` #ifdef (positive)
- `test/initramfs/src/regression/device/vt/vt_ioctl.c:199` #ifdef (positive)
- `test/initramfs/src/regression/fs/inotify/inotify_unlink.c:21` #ifdef (positive)
- `test/initramfs/src/regression/fs/procfs/proc_fd_open_fifo_after_setid.c:51` #ifdef (positive)
- `test/initramfs/src/regression/fs/tmpfile/tmpfile.c:110` #ifdef (positive)
- `test/initramfs/src/regression/fs/tmpfile/tmpfile.c:254` #ifdef (positive)
- `test/initramfs/src/regression/io/epoll/poll_err.c:59` #ifdef (positive)
- `test/initramfs/src/regression/io/file_io/fcntl_status_flags.c:177` #ifdef (positive)
- `test/initramfs/src/regression/ipc/sem/sem.c:226` #ifdef (positive)
- `test/initramfs/src/regression/ipc/sem/sem.c:483` #ifdef (positive)
- `test/initramfs/src/regression/ipc/sem/sem.c:507` #ifdef (positive)
- `test/initramfs/src/regression/memory/mmap/mmap_anonymous_fault_around.c:41` #ifdef (positive)
- `test/initramfs/src/regression/memory/mmap/mmap_anonymous_fault_around.c:163` #ifdef (positive)
- `test/initramfs/src/regression/memory/mmap/mmap_err.c:58` #ifdef (positive)
- `test/initramfs/src/regression/memory/mmap/mmap_err.c:104` #ifdef (positive)
- `test/initramfs/src/regression/memory/mmap/mmap_vmrss.c:20` #ifdef (positive)
- `test/initramfs/src/regression/memory/mmap/mmap_vmrss.c:175` #ifdef (positive)
- `test/initramfs/src/regression/memory/mmap/rev_map_common.h:112` #ifdef (positive)
- `test/initramfs/src/regression/memory/mmap/rev_map_common.h:170` #ifdef (positive)
- `test/initramfs/src/regression/network/addr_config.c:340` #ifdef (positive)
- `test/initramfs/src/regression/network/link_state.c:426` #ifdef (positive)
- `test/initramfs/src/regression/network/netlink_route.c:128` #ifdef (positive)
- `test/initramfs/src/regression/network/netlink_route.c:209` #ifdef (positive)
- `test/initramfs/src/regression/network/netlink_route.c:222` #ifdef (positive)
- `test/initramfs/src/regression/network/netlink_route.c:586` #ifdef (positive)
- `test/initramfs/src/regression/network/packet_options.c:175` #ifdef (positive)
- `test/initramfs/src/regression/network/packet_send.c:453` #ifdef (positive)
- `test/initramfs/src/regression/network/route_config.c:293` #ifdef (positive)
- `test/initramfs/src/regression/network/rtnl_ack.c:113` #ifdef (positive)
- `test/initramfs/src/regression/network/tcp_err.c:227` #ifndef (negative)
- `test/initramfs/src/regression/network/tcp_err.c:472` #ifdef (positive)
- `test/initramfs/src/regression/network/tcp_err.c:515` #ifdef (positive)
- `test/initramfs/src/regression/network/tcp_reuseaddr.c:80` #ifndef (negative)
- `test/initramfs/src/regression/network/tcp_reuseaddr.c:110` #ifndef (negative)
- `test/initramfs/src/regression/network/tcp_reuseaddr.c:203` #ifndef (negative)
- `test/initramfs/src/regression/network/udp_ancillary.c:285` #ifdef (positive)
- `test/initramfs/src/regression/network/udp_broadcast.c:151` #ifdef (positive)
- `test/initramfs/src/regression/network/udp_device.c:261` #ifdef (positive)
- `test/initramfs/src/regression/network/udp_err.c:485` #ifndef (negative)
- `test/initramfs/src/regression/process/execve/execve_comm.c:126` #ifdef (positive)
- `test/initramfs/src/regression/process/execve/execve_err.c:294` #ifdef (positive)
- `test/initramfs/src/regression/process/execve/execve_err.c:469` #ifndef (negative)
- `test/initramfs/src/regression/process/execve/execve_err.c:540` #ifdef (positive)
- `test/initramfs/src/regression/process/ptrace/read_write_regs.c:114` #ifdef (positive)
- `test/initramfs/src/regression/process/ptrace/set_options.c:188` #ifndef (negative)
- `test/initramfs/src/regression/process/signal/pidfd_send_signal.c:268` #ifndef (negative)
- `test/initramfs/src/regression/process/wait4.c:302` #ifndef (negative)
- `test/initramfs/src/regression/process/wait4.c:308` #ifndef (negative)
- `test/initramfs/src/regression/time/clock_adjust.c:230` #ifdef (positive)
