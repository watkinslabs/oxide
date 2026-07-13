# state - B810 mountfix handoff

Update: 2026-07-13.

## Current tree

- Checkout: `/home/nd/oxide/kernel`
- Branch: `B810-mountinfo-namespace-visibility`
- Base: `08a55c5f` (`main`/locally cached `origin/main`, PR #3068)
- Status: quota is merged; B810 implementation is committed, the ARM tmpfiles blocker is fixed, and final lockstep smoke/push/PR remains.
- History audit: old `quota-complete-20260712` tip is fully contained by current main; no quota commit was lost.

## B810 completed work

- `/proc/self/{mounts,mountinfo}` is caller-namespace-relative with per-open snapshots; concrete `/proc/<pid>` remains task-relative.
- Mount generation wakes mountinfo poll subscribers; `statmount`/`listmount` use caller namespace state and validate base ABI shape.
- Init mount namespace/root mount identity is pinned and preserved through absolute lookup.
- Cgroup control truncation, task placement, stale pid rejection, and populated-tree rmdir behavior are Linux-shaped.
- Reaped pidfd-pinned tasks are excluded from child, pid, process-group, and pidfd signal predicates; orphan repair reparents consistently.
- AF_UNIX, packet, TCP, UDP, and netlink blocking receive uses object-specific wait sources.
- AF_UNIX bound sockets remain reservations until `listen(2)`; dbus-broker now binds and starts normally.
- Final socket-file release tears down AF_UNIX endpoints immediately, independent of inode lifetime; Varlink workers no longer wait their 15-second idle timeout before accepting the next request.
- AF_UNIX readiness notifications carry the actual event mask, so inbound data cannot manufacture repeated edge-triggered `POLLOUT` events.
- Ext4 initializes uninitialized block bitmaps correctly and truncate reads transaction-shadow extent nodes; ARM image regression fsck is clean.
- Ext4 preserves Linux O_TMPFILE `st_nlink == 0`, propagates backend lookup errors through hardlink preflight, and keeps dirty batch metadata shadow-visible until journal/home writeback completes. Batch commit holds the transaction gate for its full lifetime, so readers never observe a partially committed metadata generation.
- Every quick boot starts from a fresh packed root image; forced smoke termination can no longer poison later boots by reusing a dirty root disk.
- AArch64 IRQ frames save/restore x19-x28 and all SVC-frame offsets have compile-time layout assertions.
- AArch64 restores each incoming task's canonical SVC frame pointer; clone/exec use task-owned syscall frames.
- Scheduler wake placement has exclusive Sleeping->Runnable ownership and handles wake-before-schedule current tasks without deferred duplicate placement.
- Fatal user faults converge through canonical group exit/zombie publication; PID1 child cleanup no longer waits for cgroup timeout.
- signalfd uses the caller task's signal source; child zombie publication precedes SIGCHLD/signalfd wake.
- epoll uses Linux-style interest/ready lists, exact per-epitem source callbacks, ET/LT/ONESHOT behavior, nested-cycle rejection, and weak watched-file backlinks released at final fput.
- poll/select use dynamic per-file sources and generation-checked prepare-to-sleep; the 20 ms correctness rescan is removed.
- timerfd publishes its source and exact monotonic poll deadline; poll/select/epoll arm scheduler deadlines rather than periodic rescans.
- Mount matrix rows 155/165/166/428-433/442/457/458/467 are honestly `PARTIAL`; stale ioctl quota wording is removed.

## Latest verification

Passed:

```
RUSTFLAGS='-Awarnings' cargo test -q -p fs --test sys_epoll_file_identity -- --test-threads=1  # 9/9
RUSTFLAGS='-Awarnings' cargo test -q -p sched -- --test-threads=1                              # 134/134
RUSTFLAGS='-Awarnings' cargo test -q -p hal-aarch64 --lib -- --test-threads=1                  # 46/46
RUSTFLAGS='-Awarnings' cargo test -q -p vfs --test mount_proc_domainname_namespace -- --test-threads=1 # 5/5
RUSTFLAGS='-Awarnings' cargo test -q -p syscalls --test mount_api_namespace_hosted -- --test-threads=1 # 3/3
RUSTFLAGS='-Awarnings' cargo check -q -p pmm -p sched -p fs -p kmain --target targets/aarch64-unknown-oxide-kernel.json -Zjson-target-spec -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem --features kmain/debug-boot
RUSTFLAGS='-Awarnings' cargo check -q -p pmm -p sched -p fs -p kmain --target targets/x86_64-unknown-oxide-kernel.json -Zjson-target-spec -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem --features kmain/debug-boot
RUSTFLAGS='-Awarnings' cargo test -q -p ext4 --test batch_commit_serialization_image -- --test-threads=1 # 1/1
RUSTFLAGS='-Awarnings' cargo test -q -p ext4 --lib -- --test-threads=1                              # 100/100
RUSTFLAGS='-Awarnings' cargo test -q -p ext4 --test rename_overwrite_image -- --test-threads=1      # 8/8
RUSTFLAGS='-Awarnings' cargo test -q -p net --lib -- --test-threads=1                               # 265/265
OXIDE_EXT4_REAL_ROOT_IMG=/home/nd/oxide/images/out/gnome-x86_64-root.img RUSTFLAGS='-Awarnings' cargo test -q -p ext4 --test real_rootfs_mkdir_repro real_hwdb_tmpfile_publish -- --ignored --exact --test-threads=1 # 1/1
SMOKE_KEEP_LOG_DIR=target/B810-final-shadow-x86 OXIDE_SMOKE_ATTEMPTS=1 ./tools/boot-smoke.sh x86 180 # basic.target in 83s; hwdb + dbus passed
OXIDE_QUICKBOOT_PROFILE=gnome OXIDE_SMOKE_ATTEMPTS=1 ./tools/boot-smoke.sh x86 180 # final basic.target in 70s
OXIDE_QUICKBOOT_PROFILE=gnome OXIDE_SMOKE_ATTEMPTS=1 ./tools/boot-smoke.sh arm # final basic.target in 74s; stock 600s default
e2fsck -fn /home/nd/oxide/images/out/gnome-x86_64-root.img     # clean
e2fsck -fn /home/nd/oxide/images/out/lite-aarch64-root.img    # clean
```

ARM GNOME artifact: `/home/nd/oxide/images/out/gnome-aarch64-root.img` was built with `./build.sh rootfs gnome aarch64`. The prior delay was not slow TCG or a stretched scheduler deadline: final fd close did not release the AF_UNIX endpoint, so each `systemd-userwork` process waited its 15-second Varlink connection idle timeout before accepting queued work. Moving endpoint teardown to final `File` release and using mask-specific AF_UNIX notifications made the early tmpfiles marker pass in 68 seconds with the stock one-attempt harness and no timeout extension.

Known unrelated hosted failure:

```
RUSTFLAGS='-Awarnings' cargo test -q -p vfs --lib tests_d4b::t1b_idmap_chown_in
# existing notify_change/idmap test returns Einval
```

## Final gate

1. Commit every intentional tracked/untracked file on B810.
2. Push, open PR, merge, and update main.

## Follow-up mount compliance

- `pivot_root`: lookup errno/order/directory checks and direct ABI coverage.
- `mount`/`umount2`: fresh mount flags, unsupported-fs false success, recursive/remount combinations, MNT_EXPIRE two-pass, MNT_FORCE.
- New mount API: complete flags, dirfd/empty-path, binary/FD fsconfig parameters, namespace permissions, idmap/propagation, detached recursion.
- `statmount`/`listmount`: requested masks, BY_FD/ns modes, topology-derived ancestry/cursor semantics.
- `open_tree_attr`: apply requested attributes rather than validation-only delegation.

## Separate known bug

- `ext4::e2fsck_image::htree_leaf_split_stays_e2fsck_clean` overcounts inode `i_blocks` after extent insertion/merge.
