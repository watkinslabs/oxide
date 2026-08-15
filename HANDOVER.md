# Handover — 2026-08-15

## Current checkout

- `main` and `origin/main` are at `0d5864180`.
- The primary checkout is clean. No feature worktrees or branches are left open; every lane below merged and was removed.
- 16 PRs merged this session: #5452 – #5467.

## The goal, and how far it got

The stated goal is a machine a person can **log in to, use a desktop on, and run normal programs on**. That is NOT met and is not close. Nothing this session reached a login prompt.

What DID change is that the two deadlocks blocking every boot were found and fixed, so the boot now gets far enough to expose the next layer of problems, and two missing filesystems landed.

## Merged work

### Boot: two deadlocks, root-caused with evidence

| What | How it was found | Result |
|---|---|---|
| The reclaim LRU lock was taken plainly on the page-free path, which also runs in interrupt context — a one-CPU self-deadlock (#5452) | watchdog `kernel_pc` → disassembly → `addr2line -i` | Boot went from dying at 14 s to reaching dbus-broker, NetworkManager, resolved and udevd at 61 s |
| `replace_mm` released the departing address space while holding `mm_pin_lock`, so every `execve` slept under a spinlock (#5454) | the held-lock trace added in #5452, which named `task/signals.rs:478` in one line | **29,889 → 0** atomic-schedule reports; boot reaches `basic.target`, logind and rtkit at 5.3 s |

Two diagnostics made those findable and are now permanent: per-frame held-lock acquisition sites captured through `#[track_caller]` (#5452), and `lock_bh` sections joining that trace (#5459) — they were the one path it could not see.

### Missing Linux features

- **Loop devices** (#5457, #5458) — `NOT FOUND` → `HAVE`. `/dev/loop0..7`, `/dev/loop-control`, the `LOOP_*` ioctls, boot-time publication. `modprobe@loop.service` now finishes instead of failing.
- **FAT/VFAT** (#5460, #5461, #5462, #5463, #5464, #5466, #5467) — `NOT FOUND` → `HAVE`, read and write. `mount -t vfat` works; files can be read, written, grown and truncated. 117 hosted tests over seven layers, every one written against `fs/fat/` in the reference first.

### Record corrections

- `scratch/system-compat.md` was re-ranked around "can a person use this machine" (#5455), its stale SMP P0 removed, and seven systems a user meets in the first five minutes added as rows.
- A claim that `simpledrm` was missing was **retracted** (#5456). It exists and always did; the claim came from grepping two files in a crate whose third file holds the implementation.

### One regression, mine, found and fixed

#5448 (earlier session) moved the debug shell to a VT so `serial-getty` could own the serial line. That broke all three in-guest probe harnesses, which drive that shell over the serial FIFO — a login prompt was swallowing their commands as usernames. Fixed in #5465 with an explicit `OXIDE_SERIAL_SHELL=1` opt-in that moves the shell and masks the getty together. Measured both ways rather than argued.

## Where the boot actually stands

Best observed x86 run: `basic.target`, dbus-broker, systemd-logind, rtkit and NetworkManager up at ~5 s, still running at 129 s. **No run has reached a login prompt.**

Three things stand between here and one, in the order they bite:

1. **`serial-getty@ttyS0` exits successfully after exactly 5.000 s and restart-loops** — 23 restarts in one 129 s boot, a metronomic 5.4 s period, exit status *success*. The exactness says a timeout is expiring rather than an error path being taken. This is the nearest thing to a login and nobody has looked at what agetty is actually doing; the probe harness (repaired in #5465) can now be pointed at it.
2. **An intermittent silent wedge at ~3.3-3.6 s**, in roughly half of boots. The log stops mid-service-startup, QEMU sits near zero CPU, and a typed serial sysrq gets no answer. No watchdog fires at all, which is worse than the spinning variant that at least reported itself.
3. **A `scheduling while atomic` storm from `wait_event.rs:143`**, `preempt_count=0x201`, `held=[]`. The empty held-list was the blindness #5459 fixed, so the next occurrence should name its lock. It has not fired since that landed — it is intermittent — so the trace's output on it is **not yet observed**.

Items 2 and 3 may be the same fault seen from two sides. Nobody has established that either way.

## Next steps, in priority order

1. **The getty restart loop.** Deterministic, reproducible, and the last thing before a login prompt. Use the repaired harness: `OXIDE_SERIAL_SHELL=1 tools/boot-smoke-fs.sh x86` gets a root shell, then read `systemctl status serial-getty@ttyS0`, the journal for that unit, and the tty's state. Do not guess from the interval.
2. **Confirm `vfat` reaches `/proc/filesystems` in the guest.** #5464 merged saying explicitly that this was never observed — only that registering it broke nothing. One harness probe answers it.
3. **FAT create/delete/rename.** Writing to a file that exists works; making one does not, so a volume's set of names is still whatever another system wrote. That is the gap between a readable medium and a usable one, and the layers under it are done and tested.
4. **The remaining Tier-1 desktop rows**, none of which exist at all: suspend/resume (`power/` is poweroff, reset, CAD and kexec only), `power_supply`, backlight, HD audio. `scratch/system-compat.md` has them with evidence.

## Working discipline that held, and should

- Every PR carries a **positive control**: the defect was reintroduced, the tests confirmed red, then restored green, and the PR body says which tests and how many.
- Every layer was read against `../oxide/reference` **before** it was written, and each deviation is a row in `scratch/known_issues.md` with its reason — not a comment.
- Boots stayed at one per lane, at the end, after the hosted gate was green. The one exception is documented: the boot-vs-boot A/B that proved the harness regression.
- One item, one lane, one worktree, removed on merge.

## Things a future session should not re-derive

- `simpledrm` exists (`drv-simplefb/src/driver.rs`). A grep of `lib.rs` and `format.rs` in that crate finds only fbdev and is misleading.
- The aarch64 target is QEMU `virt` and nothing else: the GIC driver is GICv3-only with its addresses compiled in, and exactly three properties are read from the device tree. A Raspberry Pi needs a GICv2 driver, FDT-driven discovery, SDHCI and GENET — four items, not polish. `scratch/system-compat.md` has the platform section.
- The spec-lint ratchet is red on untouched `main` (55 regressions, none from recent lanes), so every push uses `SKIP_LINT_RATCHET=1`. That is a filed `INFRA` row, not a per-lane failure.
