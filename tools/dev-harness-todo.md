# Dev/test-loop harness — to-do

Grounded in time-sinks observed in real sessions. Checkbox = not done.
Ordered by ROI. Several build on the `--id` build-namespacing (xtask `buildns`).

## Top ROI (caused the most wasted cycles)

- [ ] **Auto-reap stale qemu before every launch.** Disk write-lock + vsock-CID
  collisions killed ~5 runs/session. Add `tools/qemu-reap.sh`: find holders via
  `fuser kernel/blobs/*.img` and `kill -9 <pid>`. NOT `pkill -x qemu-system-x86_64`
  (15-char comm truncation misses it); NOT `pkill -f qemu` (SIGTERMs the bash
  tool shell). Call it at the top of every smoke/launch + the MCP `qemu_start`.
- [ ] **Make accel explicit and loud.** Default silently falls back to TCG; a
  forgotten `OXIDE_QEMU_KVM=1` turns a ~1-min boot into an ~8-min "hang" that
  reads as a crash. Auto-enable KVM when `/dev/kvm` exists; print
  `accel=tcg — set OXIDE_QEMU_KVM=1 for ~8x faster` at launch when on TCG.
- [ ] **Hosted tests for what QEMU catches slowly/flakily.** A `cargo test` SMP
  harness (N runqueues; assert `select_task_rq`/`place_runnable`/balancer
  actually spread work) and a clone-init-order test (assert fd-table/sighand/
  TLS are set BEFORE the child is made runnable). Would have caught the
  fork-wake race in ms instead of via flaky SMP boots.

## Also high value

- [ ] **A/B baseline harness** (`tools/ab-smoke.sh <commitA> <commitB>`): build
  both into separate `--id` namespaces, run the same smoke on each, diff the
  result. Turns "did my change cause this, or is it pre-existing?" (the
  arm-crash question) from a manual stash/rebuild dance into one command. This
  is the direct payoff of the build-namespacing work (`buildns`).
- [ ] **Stream logs to a stable path.** `KEEP_LOG` only writes on exit, so live
  progress means hunting an mktemp file. Always `tee` to
  `/tmp/oxide-<arch>-last.log`.
- [ ] **De-flake the login gate.** `boot-smoke-login`'s later steps
  (python3→stty) time out on fixed per-step sleeps even when they succeed. Wait
  for the shell prompt to return after each command; split "reached
  `oxide login:`" (the real gate) from "ran the full command battery"
  (separate, non-blocking).
- [ ] **Separate "boots" from "is correct."** Boot-to-login is happy-path smoke,
  not proof. A post-login probe battery (run from rcS/autologin) that exercises
  the changed surface and writes machine-readable PASS/FAIL — so "reached login"
  stops being mistaken for "works."
- [ ] **Auto-detect kernel-only changes** to skip the ~50-app rootfs restage.
  `OXIDE_SKIP_ROOTFS` exists but is easy to forget — hash the userspace inputs
  and skip the restage automatically when they're unchanged.

## In flight / done

- [x] `--id` build namespacing in xtask (`buildns`) — isolates per-build
  compile dir + images + ISO; id=None is byte-identical to today (CI-safe).
- [x] MCP `server.py`: multi-instance (per-instance free gdb/ssh ports, pcap,
  serial/qmp sockets), instance→build registry, build lock, GC of unreferenced
  builds (`keep_last=1`), `qemu_list`/`qemu_gc` tools. Verified: py_compile,
  build_id/free-port/GC-predicate logic tests, malicious-id rmtree guard.
  PENDING: a live end-to-end shakeout — launch two DIFFERENT builds concurrently
  and confirm both boot without lock conflict + GC reclaims on stop (~15-20 min
  of namespaced builds; not yet run).

## Out of scope (correctness, not harness)

- SMP=2 pre-push gate is destabilized by real AP TLB-shootdown + IST gaps — a
  kernel correctness fix (tracked in the B127 SMP work), not a harness change.
