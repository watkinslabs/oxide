# Notepad: on screen, surface at zero, desktop input is the last link — 2026-09-07

First command: `git log --oneline -8 && make windows-surface-gate && git worktree list && tools/issues.sh --query status=OPEN grep='Notepad\|bridge\|menu'`

## State (main ec81273c1)

- Static call surface closed: `crates/kernel/syscalls/tests/windows_call_surface/baseline.txt` has zero entries (134 → 0 this session: PRs #7546 window/desktop/clipboard/hook, #7547 message/timer/scroll/menu/sysparams, #7551 drag/icon/idle; #7548 warning fix). KI-0473 fixed.
- Serial "stall" was never the UART: the scheduler's cpufreq hook spun on a process-held plain spinlock inside the wakeup IRQ (PR #7545, KI-0521).
- Notepad window never reached the GNOME screen because `shmctl` answered EIDRM on segments marked SHM_DEST, which is the normal state of a GTK MIT-SHM segment; XWayland turned it into BadAccess and `mutter-x11-frames` died on every map (PR #7550, KI-0540). Acceptance run `/home/nd/oxide/acc2/` (uart-193559.log, screen-193559-after-token.ppm): Notepad is framed, titled, raised on click, paints white client + status bar.
- One wait list carries the message queue and NT objects (PR #7549, KI-0535).

## What acceptance still fails on (measured, acc2)

1. Desktop input never becomes Windows messages: zero WM_MOUSEACTIVATE/ACTIVATE/SETFOCUS/LBUTTON*/MOUSEMOVE/KEY*/CHAR in `[WINDOWS-MESSAGE-CALL]` after the harness click + typed token; paint/size messages flow. Lane `B…-desktop-input-reaches-notepad` (running at hand-off): bridge X event mask/focus/reparent → bridge frame → kernel compositor worker → GUI owner → queue wake.
2. No menu bar drawn under the title (Notepad's File/Edit/… bar). Menu-bar nonclient painting (reference `dlls/win32u/nonclient.c` nc_paint → menu.c draw_menu_bar_temp) is not implemented; spawn a lane AFTER `F1619-popup-menu-tracking-loop` merges (same files).
3. `F1619-popup-menu-tracking-loop` (KI-0538, running): popup menu window class + modal tracking loop.

## Integration recipe (unchanged; see auto-memory `union-merge-damage-checklist`)

Squash the lane to one commit (`git reset --soft $(git merge-base HEAD origin/main)`), rebase once; ledger conflict → `git checkout origin/main -- scratch/known_issues.md scratch/archive/fixed-issues.md`, re-add the lane's rows with `/home/nd/oxide/tgt-B3525/readd.py`, `--fix` again; `raw_args.rs`/tests conflicts → `union.py`, `sortraw.py`, `dedupetest.py`, `mergeasserts.py`; then hosted suites + `make windows-surface-gate` + BOTH `xtask kernel --arch … --check` (the only gates compiling target-gated files); push with the five SKIP flags (KI-0287/0318/0423/0319/0019) + SKIP_SMOKE; PR; merge; remove worktree. Acceptance: `OXIDE_NOTEPAD_ACCEPTANCE_DIR=/home/nd/oxide/accN ./tools/windows-notepad-acceptance.py` (visible QEMU window; do not close it); `native_process_identity` fails on any reused target dir (three sched rlibs), not a regression.

## Open follow-ups worth a lane

KI-0522 clipboard delay render, KI-0523 hooks not consulted by message paths, KI-0524 class keyed by name, KI-0530/0532 display config + single device, KI-0541..0545 drag/idle details, KI-0520 block test workspace-only failure, KI-0355/0356/0359 FIXED rows never archived (`issues.sh --check` noise). Then: Wine's own user32/gdi32 conformance executables under the launcher as the semantic gate.
