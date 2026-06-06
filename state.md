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

## Open / next (pick one, ship one PR)
1. **arm `smoke::ksched::smoke_rr(4)` debug-all hang** (debug-only; production/
   debug-boot arm boots fine). 4 kthreads "enter", none "done" — hangs on the
   first RESUME of a yielded kthread (5th switch). HYPOTHESIS (unconfirmed):
   arm gen-timer fires during the cooperative no-IRQ smoke because kthreads are
   spawned via new_kernel_with_irq_frame (SPSR 0x145 = IRQ UNMASKED) and the arm
   timer is armed early (x86 LAPIC is armed AFTER the smokes in run_as_task, so
   x86 stays clean). CONFIRM via qemu-MCP: qemu_start arch=aarch64
   features=debug-all; break schedule_from_irq (does it fire during smoke_rr?)
   + inspect kthread SPSR/DAIF; then fix (mask IRQs for the smoke, or arm the
   arm timer after the smokes to match x86). context_switch asm itself is correct.
2. Phase 15 acceptance (nginx/curl) or close Phase 16 after verifying.
3. console/devpts are kernel-only by design (no host tests) — NOT bugs.

## Stale BUG tasks (re-audit; several no longer repro)
- BUG H (rm -rf tmpfs rc=1): does NOT repro (rm -rf returns 0). Minor: tmpfs `ls`
  didn't list a mkdir-ed subdir (readdir nit).
- BUG A (no echo), C (cgroup ENOTEMPTY), G (getty respawn delay): re-verify on
  the current build before working — much has changed.

Author = Chris Watkins, no AI trailers. spec-lint clean + both arches build
before every PR.
