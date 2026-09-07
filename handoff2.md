# Notepad: framed, focused, caret blinking; accepted input is never retrieved — 2026-09-07

First command: `git log --oneline -8 && make windows-surface-gate && git worktree list && tools/issues.sh --query status=OPEN grep='Notepad\|bridge\|menu'`

## State (main 89d371a11)

- Static call surface closed: `crates/kernel/syscalls/tests/windows_call_surface/baseline.txt` has zero entries (134 → 0 this session: PRs #7546 window/desktop/clipboard/hook, #7547 message/timer/scroll/menu/sysparams, #7551 drag/icon/idle; #7548 warning fix). KI-0473 fixed.
- Serial "stall" was never the UART: the scheduler's cpufreq hook spun on a process-held plain spinlock inside the wakeup IRQ (PR #7545, KI-0521).
- Notepad window never reached the GNOME screen because `shmctl` answered EIDRM on segments marked SHM_DEST, which is the normal state of a GTK MIT-SHM segment; XWayland turned it into BadAccess and `mutter-x11-frames` died on every map (PR #7550, KI-0540). Acceptance run `/home/nd/oxide/acc2/` (uart-193559.log, screen-193559-after-token.ppm): Notepad is framed, titled, raised on click, paints white client + status bar.
- One wait list carries the message queue and NT objects (PR #7549, KI-0535).

## What acceptance still fails on (measured, acc9: full console capture + traces)

Merged since the wave: #7553/#7555/#7556/#7558 popup menu window, resumable tracking loop, menu bar paint/hit test/entry, bar items in the loop; #7559 kernel text runs present in order; #7554/#7557 bridge input retargeting and child configure; #7562 retrieval-time hardware ladder (WM_MOUSEACTIVATE/SETCURSOR/PARENTNOTIFY, PM_NOREMOVE paint readiness); #7560/#7564/#7565/#7566 harness: whole oops retained, console drained for the whole run (earlier "zero input" logs ended before the click), bounded wait for the desktop to frame the window, per-record traces on both sides of the compositor socket.

Run acc9 (`/home/nd/oxide/acc9/uart-1200805.log`): Notepad framed, activated, caret visible in the edit control (`screen-*-after-token.ppm`). Focus record accepted → WM_ACTIVATE/WM_SETFOCUS retrieved. Click + typed token: bridge emits Pointer/Key/Text for hwnd 2, kernel logs `[WINDOWS-BRIDGE-EVENT] op=0105/0103/0104 hwnd=2 accepted=1` for all 55 records, no `[WINDOWS-BRIDGE-DOWN]`, yet Notepad's thread never retrieves again after 55.989 (zero GETMESSAGE/MESSAGE-CALL for 0x200/0x201/0x21/0x100/0x102, zero CALLBACK-CALL). Lane `B…-hardware-records-never-retrieved` (running at hand-off) owns it: wake predicate/mask for QS_MOUSE/QS_KEY vs the posted path, the #7562 ladder never arming its callback, or take/peek filtering hardware entries.

Also still open for a usable Notepad: no menu bar painted yet on screen (bar code merged; verify after input lands), KI-0581 window-menu icon, KI-0585 bar text one flush late, KI-0592 chained EDIT text coverage.

## Integration recipe (unchanged; see auto-memory `union-merge-damage-checklist`)

Squash the lane to one commit (`git reset --soft $(git merge-base HEAD origin/main)`), rebase once; ledger conflict → `git checkout origin/main -- scratch/known_issues.md scratch/archive/fixed-issues.md`, re-add the lane's rows with `/home/nd/oxide/tgt-B3525/readd.py`, `--fix` again; `raw_args.rs`/tests conflicts → `union.py`, `sortraw.py`, `dedupetest.py`, `mergeasserts.py`; then hosted suites + `make windows-surface-gate` + BOTH `xtask kernel --arch … --check` (the only gates compiling target-gated files); push with the five SKIP flags (KI-0287/0318/0423/0319/0019) + SKIP_SMOKE; PR; merge; remove worktree. Acceptance: run DETACHED (`setsid nohup` a script that sets `OXIDE_NOTEPAD_ACCEPTANCE_DIR=/home/nd/oxide/accN` and runs `./tools/windows-notepad-acceptance.py`, then touch a DONE file; see `/home/nd/oxide/acc8/run.sh`) because the session's low-memory guard kills foreground/background runs during image assembly (page cache, not real pressure); visible QEMU window, do not close it. `native_process_identity` fails on any reused target dir (three sched rlibs), not a regression.

## Open follow-ups worth a lane

KI-0522 clipboard delay render, KI-0523 hooks not consulted by message paths, KI-0524 class keyed by name, KI-0530/0532 display config + single device, KI-0541..0545 drag/idle details, KI-0520 block test workspace-only failure, KI-0355/0356/0359 FIXED rows never archived (`issues.sh --check` noise). Then: Wine's own user32/gdi32 conformance executables under the launcher as the semantic gate.
