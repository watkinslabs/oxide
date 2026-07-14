# mountfix - B810 current status

Status: VERIFIED 2026-07-13 - `B810-mountinfo-namespace-visibility`.

## Result

- Original mount visibility/cgroup/userdbd path is implemented: caller-relative proc mount views, stable root mount identity, namespace-relative statmount/listmount, cgroup lifecycle fixes, and object-specific receive waits.
- ARM intermittent journal-flush/userdbd faults were not an ext4 corruption recurrence. Symbolized faults proved control/context corruption.
- Root causes fixed: duplicate scheduler wake placement, incomplete AArch64 IRQ preservation, cross-task per-CPU SVC-frame aliasing, fatal-exit divergence, and signalfd/zombie publication ordering.
- epoll was reworked around interest and ready lists. poll/select now share exact per-file wait sources and a race-free generation handshake.
- timerfd readiness uses a real scheduler deadline. No 20 ms correctness polling remains.
- Quota work is already merged in main. History audit found zero quota commits absent from HEAD.

## Evidence

- Epoll hosted suite: 9/9.
- Scheduler hosted suite: 134/134.
- AArch64 HAL suite: 46/46.
- Mount proc/domain namespace suite: 5/5.
- Mount API namespace suite: 3/3.
- Full affected x86_64 and aarch64 kernel target checks pass.
- Previous ARM root image post-run `e2fsck -fn` was clean.

## Remaining before publication

- Add all intentional files, commit B810, push, PR, merge, update main.

## Audited follow-up

The mount visibility fix is complete, but full Linux mount-syscall parity is not. Matrix rows now say `PARTIAL` and name the remaining flag, error-order, namespace, idmap, topology, and modern mount-API gaps. These should be closed in focused follow-up branches after B810 is published.
## 2026-07-13 final ext4/hwdb investigation

- Reproduced systemd-hwdb's Linux O_TMPFILE publication sequence: initial link returns EEXIST, temporary link succeeds, then rename replaces `hwdb.bin`.
- Fixed ext4 inode wrapping to preserve on-disk `i_nlink == 0` for anonymous tmpfiles.
- Added result-preserving child lookup so hardlink preflight does not collapse backend EIO into ENOENT.
- Root-caused intermittent hardlink EIO to batch commit draining the metadata shadow before home writes completed. Batch commit now keeps the committed generation shadow-visible, holds the transaction gate against mutators, and retires the shadow only after successful writeback.
- Added a deterministic blocking-device regression proving metadata reads remain coherent while commit home writes are stopped.
- Final x86 boot reaches basic.target with hwdb and dbus-broker successful. ARM's tmpfiles delay was an AF_UNIX endpoint-lifetime bug: socket teardown rode `InetSocket::drop` instead of final `File` release, serializing userwork accepts behind 15-second idle timeouts. Final file release now closes the endpoint, AF_UNIX emits mask-specific readiness notifications, and the early tmpfiles marker passes in 68 seconds without a timeout override.
- Final lockstep gate reaches basic.target in 70 seconds on x86 and 74 seconds on ARM; ARM used the stock 600-second harness default and required no extension.
