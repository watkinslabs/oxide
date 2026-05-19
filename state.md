# state — hand-off

Branch: main (clean). spec-lint clean, 1149 hosted tests pass,
both arches build, x86 smoke 14s + arm smoke 18s green.

## Session tally (PRs #1172–#1176)

| PR    | What |
|-------|------|
| B42   | aarch64→x86 syscall translator rebuild; ARM smoke ELF uses generic NRs |
| B43   | execve user-stack VMA gets `VmaFlags::GROWSDOWN` (per `docs/31§5`) |
| F123  | vendor dhcpcd 10.3.2 (per-arch static-musl), stage `/sbin/dhcpcd`, `/etc/dhcpcd.conf`, `/var/{db,run}/dhcpcd`, rcS launch (gated); `sys_socketpair` mask 0xFF→0xF |
| F125  | epoll waitqueue (`sched::live::EPOLL_GLOBAL_WAIT` + `notify_epoll_waiters`); `UnixMsgPair` for AF_UNIX SEQPACKET/DGRAM socketpair |
| D32   | `try_grow_stack` cap 64 KiB → 8 MiB (RLIMIT_STACK-style); fixes wide musl init frames |

## What works end-to-end now

- **aarch64 syscall ABI** — comprehensive arm-generic → x86 translation table; epoll/inotify/shm/rlimit/renameat2 etc. all routed, not silently aliased into wild syscalls
- **demand-grow stack** — execve flags GROWSDOWN; auto-extends up to 8 MiB on per-fault basis; a 140 KiB sub-sp,N is one grow, not 35
- **epoll blocking** — `sys_epoll_wait` parks on the global waitlist when timeout!=0 + no events ready; `UnixPair::write`, `UnixMsgPair::send`, `UnixDgramQueue::push` all wake parkers; was a 700k-syscalls/min spin in dhcpcd's privsep child
- **AF_UNIX socketpair** — STREAM (byte ring) and SEQPACKET/DGRAM (msg-pair) both supported; framing layer handles message-boundary preservation
- **dhcpcd substrate** — binary staged, conf staged, rcS will launch when `/etc/oxide-dhcpcd-enable` marker is present

## Open next (priority order)

1. **dhcpcd `0x4925f9` crash** — children SIGSEGV on indirect jump to a heap address (likely function-pointer corruption from an earlier syscall returning wrong data). Repro: stage `/etc/oxide-dhcpcd-enable` in rootfs, smoke; children loop crash, init respawns, boot never reaches login. Auto-launch gated absent until fixed
2. **K10 eBPF rest** — path-sensitive verifier (reg types, scalar bounds) → JIT; structural-only today
3. **K13 DRM/KMS atomic modeset** — property tables + real atomic-commit
4. **getty wedge B40** — real tty-ioctl/termios bug behind the `/bin/login` direct workaround in inittab
5. **DNS / TLS userspace** — depends on dhcpcd actually leasing
6. **per-fd targeted epoll wakes** — current model is global broadcast; needs Inode poll-wait hook without dragging `sched` into `vfs`

## Repro for dhcpcd-0x4925f9 hunt

```sh
# stage the dhcpcd-enable marker into rootfs:
cat >> tools/xtask/src/main.rs <<'PATCH'
# (inside cmd_rootfs near oxide-init-smokes staging):
put(&stage("oxide-dhcpcd-enable", b"1\n")?, "/etc/oxide-dhcpcd-enable")?;
PATCH

cargo run -p xtask -- rootfs --arch x86_64
FEATURES="debug-syscall,sched/debug-syscall,debug-irq" \
  ./tools/boot-smoke.sh x86 60
# look for "[FAULT] sigsegv: kill tid=NNNN ... rip=00000000004925f9"
# the rip address is NOT in dhcpcd's .text (ends 0x4301c9) —
# it's a heap address jumped to via corrupted function pointer.
```

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch — `gh pr merge --merge` handles
  integration server-side
- Never delete branches (`git branch -d/-D`) — preserve all
- spec-lint clean before every commit + PR
- Debug-syscall trace floods UART; smoke timeouts under it need
  ~3× normal; don't conclude "wedge" from a short-window trace

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick from "Open next". Item 1 (dhcpcd `0x4925f9`) is the
last piece for end-to-end DHCP. The fix is likely in the
syscall-return data layer (some struct field returned by us
differs from Linux, dhcpcd treats it as a function ptr).
