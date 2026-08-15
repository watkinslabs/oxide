# state — 2026-08-15

`main` = `0d5864180`, clean, no open worktrees or branches.

## This session

16 PRs, #5452 – #5467. Full account in `HANDOVER.md`; SHAs in git log.

- Two boot deadlocks fixed (reclaim LRU lock IRQ-safety; `replace_mm` releasing the old address space under a spinlock). Boot went from dying at 14 s to `basic.target` + logind + dbus at 5.3 s, still up at 129 s.
- Loop devices and FAT/VFAT both `NOT FOUND` → `HAVE`. FAT reads and writes.
- Held-lock trace now names the acquisition site, including `lock_bh` sections.
- Retracted a wrong claim that `simpledrm` was missing.
- Fixed a regression from #5448 that had broken all three in-guest probe harnesses.

## Still open

No boot has reached a login prompt. In the order they bite:

1. `serial-getty@ttyS0` exits successfully every 5.000 s and restart-loops.
2. Intermittent silent wedge at ~3.3-3.6 s, ~half of boots, no watchdog output.
3. `scheduling while atomic` from `wait_event.rs:143`, `preempt_count=0x201`. The trace that would name its lock landed after it last fired, so its output is unobserved.

(2) and (3) may be one fault; nobody has established that.

## First command next session

```
OXIDE_SERIAL_SHELL=1 tools/boot-smoke-fs.sh x86
```

Then, from the root shell it gives: `systemctl status serial-getty@ttyS0` and that unit's journal. Read what agetty does rather than inferring from the 5 s interval.
