# state.md — session handoff

## Headline
Kernel boots to graphical.target + gdm; **greeter still not rendered.** The
greeter blocker is now precisely specced, not guessed: see
**`docs/60-udev-kernel-contract.md`** (merged #2332) — the full kernel↔udev
requirements checklist R01–R31 with status + an end-to-end acceptance gate (§11).

## The day's arc (READ THIS)
1. The #2330 driver merge broke the BUILD and dropped transitional virtio-blk →
   kernel panicked at 2.3s. `xtask artifacts` silently re-exported the stale
   kernel.elf, so hours of "udev/logind broken" debugging ran against DEAD
   kernels — false conclusions. (Memory: [[stale-artifacts-mask-kernel-bugs]].)
2. Repaired: #2331 (compile), oxide-images `disable-legacy=on` (modern virtio-blk
   the refactored kernel binds). Kernel boots again.
3. Wrote doc 60 (the udev contract) to stop the whack-a-mole.

## Merged this session (kernel main): #2324–#2329, #2331, #2333
udev RECEIVE + PROCESS path is DONE (R01–R09,R20,R24–R29): SCM_CREDENTIALS
(#2327 — THE key fix), MSG_PEEK/TRUNC, nl_groups, poll-wake, sendmsg coalesce
(#2329), pidfd poll (#2326), /proc/<pid>/fd (#2328), af_unix listener poll_subs
(#2333, R22). Result: `/run/udev/data/c226:0` gets `G:master-of-seat`.
oxide-images (local, no remote): `c1e9021` virtio-blk disable-legacy=on.

## LIVE greeter blocker (doc 60 R21 + R30/R31)
- **R30/R31 (the greeter gate):** logind does NOT create `/run/systemd/seats/seat0`
  → seat0 not CanGraphical → gdm launches no greeter. logind IS functional (owns
  `org.freedesktop.login1` = `:1.9`; earlier "activatable" was a bad-boot
  artifact). It just never attaches card0. `/run/udev/tags/` is absent (udevd
  writes /run/udev/data but not the tag index). UNKNOWN whether systemd 257 needs
  /run/udev/tags/ or reads tags from /run/udev/data/ — VERIFY against systemd
  source before implementing.
- **R21 (introspection blocker):** `udevadm settle/info/trigger` time out (udevd
  control socket). #2333 may help (targeted listener wake); re-test. Fixing this
  unblocks `udevadm info /dev/dri/card0` (see TAGS) + `udevadm trigger` to diagnose R30.

## First task next session
`git checkout main && git pull`. Work doc 60 R21→R30/R31. Concretely:
1. Verify #2333 fixed udevadm control (boot, `udevadm settle`; needs a clean boot —
   see [[boot-intermittency-and-debugfs-gotchas]], boots are ~50% flaky, re-run).
2. If udevadm works: `udevadm info /dev/dri/card0` — does it show TAGS=master-of-seat
   and is the device in logind's view? `loginctl seat-status seat0`.
3. Determine (systemd 257 source) how logind enumerates master-of-seat: /run/udev/tags/
   vs /run/udev/data/. Fix whichever the kernel/udev-flow breaks.
4. Also audit doc 60 R10–R19 (per-subsystem uevent keys + sysfs attrs).

## Diagnosis harness (USE — ends the thrash)
- Inject oxdiag oneshot on a FRESH never-booted img via ONE `debugfs -w -f cmdfile`
  session (dumps to /dev/ttyS0 at graphical.target). NEVER debugfs-edit a booted
  (dirty) metadata_csum img — corrupts it. Boots are flaky: loop boot 2-3× until
  `grep -c OXDIAG_START` ≥1. Unit must NOT have a `Wants=`+`WantedBy=` cycle.
- sudo/loop-mount are BLOCKED in the sandbox. Rootfs `/` is uid-1000 (harmless).
- Ledger metadata/index.md: B next=315(→used by #2333? verify), D next=119.
