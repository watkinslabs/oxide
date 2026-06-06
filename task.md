# Tasks

Snapshot at session exit. Primary goals (vendor arm builds, arm lockstep, distro
progress) all DONE. See state.md for full hand-off + the critical pkill/rm-rf
rule + boot-verify recipes.

## Done this session (merged)
- [x] GOAL: all vendor arm cross-builds work — 45/46 both arches (#1541/#1542).
      systemd not rebuilt (meson resource-killed) but unchanged + prebuilt works.
- [x] GOAL: arm at par with x86 — boots→systemd→login→shell, uname=aarch64.
- [x] Boot PID 1 via real execve path (B54) — systemd as PID1, no smoke/global-AS.
- [x] Delete synthetic bringup smoke + global-AS fallback.
- [x] Extract syscalls into own crate (kernel = glue).
- [x] Phase 14 (VMM advanced) closed (#1543) — mremap/mprotect/madvise/file-mmap.
- [x] BUG F: AF_UNIX SCM_CREDENTIALS over socketpairs (#1544) — systemd handoff.
- [x] net host-buildability restored (#1545) — 171 net oracle tests unlocked.
- [x] BUG D/E (find/ls *at dirfd; /dev/console fchown) — prior sessions.

## Done (later sessions)
- [x] #8 Limine removal (arm) — DONE #1549 (F378). arm boots GRUB EFI-stub
      `linux` → arm64 Image + PE header + self-boot MMU trampoline → login.
      Limine gone on both arches. Boots UP (see follow-on below).

## Open
- [ ] arm SMP via PSCI CPU_ON (follow-on to #1549) — Limine used to start the
      secondaries; GRUB path does no AP bring-up. selfboot.rs lays `_sb_ap_l0`;
      wire publish_psci_ap_params + bring_up_aps_psci + DTB /cpus. Then SMP=2
      arm smoke + `-accel tcg,thread=multi`.
- [ ] python3 broken in rootfs: "No module named 'encodings'" (stdlib path).
      NEW finding; distro completeness; verify-left-able.
- [ ] Phase 15 acceptance: clean loopback nc/ping test (net bins present, 171
      oracle tests pass, lo in /proc/net/dev) → close Phase 15 if green.
- [ ] Phase 16 real namespace isolation — unshare/setns are id-tracking substrate
      (F100-F107), NOT real isolation. (P16-01 UTS-fork-inherit attempt ABANDONED:
      regressed the boot; unmerged; do NOT merge.)
- [ ] smoke_rr arm debug-all hang (debug-only; production/debug-boot arm fine).
      Needs disk+gdb arm-debug — qemu-MCP can't (boots stale arm grub ISO).
- [ ] BUG C cgroup ENOTEMPTY on destroy; BUG G getty respawn delay — re-verify on
      current build (may no longer repro, like BUG H rm-rf-tmpfs which did NOT).
- [ ] phases 17–35 (docs/00§3): dynamic linker, libc/NSS/PAM, system manager,
      RPM, tty+login, io_uring, ptrace, bpf/seccomp, etc. — deep feature work.

## Stale / not-reproducing
- BUG H (rm -rf tmpfs rc=1): does NOT repro (returns 0). Closed.
- BUG A (no echo): re-verify on current build before working.
