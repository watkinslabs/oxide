# Round 2 Handoff

Date: 2026-06-28
Repo: `/home/nd/oxide/kernel`
Branch: `F649-vfs-object-model`

## Rules

- QEMU boot probes must be capped at 60 seconds: use `./runboot.sh 60 ...`.
- No masks, stubs, or fake-success compatibility shims for Linux-visible behavior.
- Do not advertise BPF LSM as enabled until it actually enforces policy.
- Do not revert unrelated VFS/MM work from other agents.

## Landed In This Worktree

- Ext4 fallocate/extent writing now uses real sorted extent insertion, split propagation, root promotion, and append through the insertion path.
- Tmpfs fallocate, memfd seals, socket timestamp options, `O_CLOEXEC`, stat-family unaligned user-buffer writes, and proc-fd link follow behavior are implemented.
- Procfs is a procfs-owned structure, not devfs-backed:
  - `/proc` root is `ProcRootInode`.
  - `/proc/sys`, `/proc/net`, and `/proc/self` are reached through procfs-owned `PROC_REG` kernfs entries where appropriate.
  - `/proc/self` and PID entries are live/dynamic.
  - `/proc/modules`, `/proc/net/dev`, route, tcp, udp, unix, snmp, arp, and if_inet6 are live inode implementations where available.
- `autofs` is implemented as a real filesystem/control surface:
  - Built-in autofs filesystem with Linux magic.
  - `/dev/autofs` misc device `10:236`.
  - Mount data parses `fd=...`.
  - Pipe file reference is captured at mount/SETPIPEFD time.
  - Missing-direct packets are sent to the daemon.
  - Control ioctls cover version/proto, openmount, ready/fail, timeout, setpipefd, ismountpoint, askumount, closemount, and catatonic.
- `binfmt_misc` is implemented as a real mounted filesystem:
  - `status`, `register`, and rule files.
  - Linux-style registration string parsing.
  - Global enabled/disabled state.
- The old image-side masks for autofs/binfmt were removed from `oxide-images/imagectl`.
- BPF LSM foundation is present:
  - `BPF_LINK_CREATE`
  - `BPF_LSM_MAC`
  - fd-backed BPF LSM link inode
  - open/openat file-open hook entry point

## Not Done

- `/proc/sys/fs/binfmt_misc` still failed systemd's boot-time `ConditionPathExists` in the latest 60-second live-gnome boot, even though the in-kernel procfs smoke resolver can resolve it. This is now in the VFS/procfs mount-path domain.
- Autofs is not fully Linux-complete yet:
  - only one pending wait token is tracked;
  - concurrent automount triggers can return `EBUSY`;
  - lookup returns `ENOENT` after trigger and relies on daemon mount/retry rather than full revalidation;
  - the boot log still contains the systemd/PID1 `autofs4` module probe message.
- BPF LSM is not complete:
  - no real BPF bytecode execution/enforcement;
  - no full BTF hook ID/name resolution;
  - no map-of-maps;
  - no systemd `RestrictFileSystems=` cgroup/filesystem-magic policy enforcement.
- Do not add `bpf` to `/sys/kernel/security/lsm` until the above BPF enforcement exists.
- The separate MM/VFS file-backed-page lifetime issue remains outside this scope.

## Last Known Verification

- `cargo fmt --check` passed in `kernel`.
- `cargo check -p fs -p syscalls` passed.
- `cargo check -p procfs -p fs -p syscalls` passed.
- `cargo test -p procfs proc_sys_resolves_own_tree -- --nocapture` passed.
- `cargo run -p xtask -- kernel --arch x86_64` passed.
- Earlier `cargo run -p xtask -- kernel --arch aarch64` passed before the last procfs root-child adjustment; rerun before claiming final dual-arch coverage.
- Latest QEMU probe was capped at 60 seconds and reached `BOOT_DONE`, but still logged:
  - `Failed to find module 'autofs4'`
  - `BPF LSM hook not enabled in the kernel, BPF LSM not supported.`
  - `ConditionPathExists=/proc/sys/fs/binfmt_misc` unmet

## Handoff To Other Developers

- VFS/procfs developer: systemd still cannot see `/proc/sys/fs/binfmt_misc` through the boot-mounted path. The procfs internal smoke path resolves it, so inspect mounted dentry crossing, mount namespace state, cached dentries, and runtime `/proc` root wiring.
- Autofs/VFS developer: make automount waits Linux-like: multi-token waits, daemon READY/FAIL revalidation, correct interruption cleanup, and real concurrent lookup behavior.
- BPF developer: implement actual BPF LSM execution/enforcement before exposing `bpf` in the LSM list.
- MM/VFS developer: fix file-backed/pagecache frame lifetime so mapped frames are not freed while PTEs still point at them.
