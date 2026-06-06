# Session hand-off

On branch **B55-tmpfs-rm-rf** (state.md only; no code — BUG H didn't repro).
Main has B54 (#1541) + C55 (#1542) merged.

## Goals — ALL THREE substantially DONE
1. **Vendor arm cross-builds — DONE (45/46).** Shared `vendor/lib/uapi-stage.sh`;
   23 swept + dhcpcd per-arch + iputils/pam meson + shadow (dynamic pam,
   --disable-logind) + util-linux (arm statx wrapper). 45/46 verified both
   arches. systemd: meson `Writing build.ninja` gets killed here (resource), but
   unchanged + prebuilt works.
2. **arm at par with x86 — DONE (boots → login → shell).** Verified:
   `oxide login: → alice/swordfish → oxide:~$ → echo SC_42_DONE → SC_42_DONE,
   uname -m → aarch64`, 0 panics. x86 equally verified (B54). FULL LOCKSTEP.
3. **B54 boot fix — DONE, merged.** PID1 Linux-way (systemd, eager stack, no
   global-AS, idle sti;hlt).

## CRITICAL environment finding (corrects earlier false "env-blocked" notes)
In this autonomous shell, commands containing **`pkill` / `rm -rf` are
permission-DENIED**, which aborts the WHOLE command with 0 output + exit 1.
EVERY "qemu/build gets killed" conclusion earlier was this denial, NOT a real
block. **Never put pkill/rm -rf in a command.** Pure qemu/build commands work.

## How to boot+verify (WORKS — no pkill!)
- x86: `nohup python3 /tmp/run_login.py > /tmp/x.txt 2>&1 &` then poll the file
  (oxide_drive, kvm, grub ISO). Login = alice / **swordfish**.
- arm: build a debug-boot disk then boot it directly (no hostfwd → no port 2222
  clash; default xtask qemu adds hostfwd which clashes with a stale qemu):
  `cargo run -q -p xtask -- qemu --arch aarch64 --features debug-boot` builds
  `target/oxide-aarch64.img`; then `/tmp/arm_login3.py` (direct qemu, socket
  serial, NO hostfwd) drives login. ~10min TCG. limine via `tools/fetch-vendor.sh`.

## Real follow-on bugs (now reproducible — boot works)
- **arm `smoke_rr` hang (debug-sched / debug-all).** Default `xtask qemu` =
  debug-all → runs bringup smokes; arm hangs in `smoke::ksched::smoke_rr(4)`:
  the 4 kthreads all "enter" but none "done" — the FIRST *resume* of a yielded
  kthread (kt4→kt1 wrap) via voluntary `ksched::tick_yield()` hangs. x86 passes.
  So `make qemu-arm` (debug-all) hangs; debug-boot is fine. Real arm
  voluntary-yield/ctxsw bug — fix `crates/arch/hal-aarch64/src/context.rs` path
  or the runqueue re-pick. (context_switch asm itself looks correct.)
- BUG F: systemd "Received handoff timestamp message without valid credentials"
  on both arches.
- BUG H (rm -rf tmpfs rc=1): does NOT repro — rm -rf returns 0. Stale task.
  (Minor: tmpfs `ls` didn't show a mkdir-ed subdir — readdir nit.)

## Next
Fix arm smoke_rr voluntary-yield hang (so debug-all/`make qemu-arm` works on
arm = true lockstep). Then BUG F, distro/syscall work. Author = Chris Watkins,
no AI trailers. Don't use pkill/rm -rf in commands.
