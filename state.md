# Session hand-off

On **main** unless noted. Extraordinary autonomous session — 8 PRs merged.

## CRITICAL environment rule (read first)
In this autonomous shell, any command containing **`pkill` / `rm -rf` is
permission-DENIED** → the WHOLE command aborts with 0 output + exit 1. NEVER use
them. Every earlier "qemu/build gets killed / env-blocked" note was THIS, not a
real block. Pure qemu/build/cargo-test commands work.

## Boot + verify (works, no pkill)
- x86: `nohup python3 /tmp/run_login.py &` → read /tmp/oxide-sc.log. Login =
  alice / **swordfish**. oxide_drive boots target/oxide-x86_64-grub.iso.
- arm: `cargo run -q -p xtask -- qemu --arch aarch64 --features debug-boot`
  builds target/oxide-aarch64.img (its qemu launch then fails on a stale
  hostfwd:2222 — harmless, disk is built), then `nohup python3 /tmp/arm_login3.py
  &` boots it directly (socket serial, NO hostfwd) → /tmp/oxide-arm3.log. ~10min
  TCG. limine via `tools/fetch-vendor.sh` if vendor/limine empty.
- Rebuild x86 ISO after kernel change: `xtask grub --arch x86_64 --features
  debug-boot --build-only`. qemu-MCP also works (mcp__qemu__qemu_start etc.).

## Merged this session
- #1541 B54: PID1 Linux-way boot (systemd, eager stack, no global-AS, idle sti;hlt).
- #1541/#1542: vendor arm cross-builds 45/46 (uapi-stage.sh; shadow dynamic-pam
  +--disable-logind; util-linux arm statx; iputils/pam meson). systemd not
  rebuilt (meson build.ninja resource-killed) but unchanged + prebuilt works.
- #1543: Phase 14 (VMM advanced) marked done — mremap/mprotect/madvise/file-mmap
  all impl + 108 vmm tests + both arches boot real userspace.
- #1544: BUG F — AF_UNIX SCM_CREDENTIALS over socketpairs (send-time cred stamp +
  recvmsg_unix_msgpair). systemd "without valid credentials" gone BOTH arches.
- #1545: net host-buildability restored (gated kernel-only timer fns) → 171 net
  oracle tests now run + pass.
- **arm at FULL lockstep**: boots→systemd→login→shell, uname=aarch64, 0 panics.

## Master-plan status (00§3)
- Phases 0–14 done. Phase 15 (docs/25) mostly impl: AF_INET6 (sock_v6/ipv6/ndp/
  icmpv6 + 171 net tests), AF_PACKET (dhcpcd), sendmmsg/recvmmsg, SCM_CREDS(#1544)
  all done; remaining gate = acceptance (nginx+curl over loopback+virtio-net) —
  needs a boot/network session. Phase 16 (namespaces) audited: unshare/setns/
  pivot_root + nscg crate already implemented — verify + close like Phase 14.
- Pattern: phase statuses LAG the code; audit before building (verify-left).

## System health: x86 boot log is CLEAN
Only warning is `Failed to find module 'autofs4'` (systemd automount; benign,
handled gracefully — do NOT stub it, that'd be a façade). Both arches boot →
login → shell. The quick-win bug surface is exhausted; remaining work is feature
development (multi-session), not bug-fixing.

## qemu-MCP arm GOTCHA (cost me an iteration)
`mcp__qemu__qemu_start arch=aarch64` boots **target/oxide-aarch64-grub.iso**,
which is STALE (xtask grub --arch aarch64 is unsupported, so it's never rebuilt)
→ the MCP boots a pre-current kernel. Its results are INVALID for current main.
For current-main arm debug use the DISK path: `xtask qemu --arch aarch64
--features <set>` rebuilds target/oxide-aarch64.img, then arm_login3.py (or add
-s -S to a direct qemu on the disk for gdb). x86 MCP is fine (ISO rebuilds).

## Open / next — all are multi-session FEATURE work, not quick fixes
1. **arm `smoke_rr(4)` debug-all hang** — debug-only (production+debug-boot arm
   boot to login+shell fine). MCP can't debug it (stale arm ISO, above). Needs a
   disk+gdb arm-debug setup. Hypothesis: arm timer IRQ fires during the no-IRQ
   cooperative smoke (kthreads SPSR 0x145 IRQ-unmasked). LOW priority (debug-only).
2. **Phase 15 acceptance**: nginx/curl over loopback (the `net udp lo round-trip`
   smoke already passes; 171 net oracle tests pass). Needs the userspace bins in
   the rootfs + a boot/network run. Close Phase 15 only after this.
3. **Phase 16 real isolation**: unshare/setns handle all CLONE_NEW* but the impl
   is id-tracking "substrate" (F100-F107), NOT full isolation (separate mount
   tables / pid translation / net stacks). Genuinely OPEN — real multi-session work.
4. console/devpts kernel-only by design (no host tests) — NOT bugs.

## Stale BUG tasks (re-audit; several no longer repro)
- BUG H (rm -rf tmpfs rc=1): does NOT repro (rm -rf returns 0). Minor: tmpfs `ls`
  didn't list a mkdir-ed subdir (readdir nit).
- BUG A (no echo), C (cgroup ENOTEMPTY), G (getty respawn delay): re-verify on
  the current build before working — much has changed.

Author = Chris Watkins, no AI trailers. spec-lint clean + both arches build
before every PR.
