# Notepad: click and typing reach the edit control; the typed text is not yet on screen — 2026-09-07

First command: `git log --oneline -8 && make windows-surface-gate && git worktree list && tools/issues.sh --query status=OPEN grep='Notepad\|bridge\|menu'`

## State (main e351002a1)

- Static call surface closed: `crates/kernel/syscalls/tests/windows_call_surface/baseline.txt` has zero entries (134 → 0 this session: PRs #7546 window/desktop/clipboard/hook, #7547 message/timer/scroll/menu/sysparams, #7551 drag/icon/idle; #7548 warning fix). KI-0473 fixed.
- Serial "stall" was never the UART: the scheduler's cpufreq hook spun on a process-held plain spinlock inside the wakeup IRQ (PR #7545, KI-0521).
- Notepad window never reached the GNOME screen because `shmctl` answered EIDRM on segments marked SHM_DEST, which is the normal state of a GTK MIT-SHM segment; XWayland turned it into BadAccess and `mutter-x11-frames` died on every map (PR #7550, KI-0540). Acceptance run `/home/nd/oxide/acc2/` (uart-193559.log, screen-193559-after-token.ppm): Notepad is framed, titled, raised on click, paints white client + status bar.
- One wait list carries the message queue and NT objects (PR #7549, KI-0535).

## What acceptance still fails on (measured, last full run `/home/nd/oxide/tgt-B3547/acc/`)

Merged since the previous note: #7568 retrieval stage compared hardware messages against the raw zero filter (every mouse/key message dropped); #7569 thread-state classes; #7570 phantom nt_window tests made real; #7571 console reader kept the run's tail (two "wedges" were capture artifacts); #7572 ONE win32u routing chain (the raw entry routed twelve fewer families; unclaimed count now 0 on the real path; hosted coverage test pins every family walked); #7574 InvalidateRect had a second, divergent implementation (erase flag dropped, no children); #7575 debug-channel header never wrote the resolved flags back (every trace site re-entered the kernel); #7576 show invalidates the frame so WM_NCPAINT is sent; #7577 NT heap: regions/blocks instead of a mapping per allocation (164 -> 6 address-space ops per run).

Now: framed, focused, caret visible; click -> WM_LBUTTONDOWN, typing -> ~60 WM_CHAR handled by the edit (EN_CHANGE notifications flow), a typed character invalidates a rect on the edit and WM_PAINT is retrieved; UART audit clean. Still red: (1) the typed token is not painted within the harness window (KI-0608 open: pump was ~1 message / 1.6 s before #7575/#7577; the first acceptance on main with both merged has not run yet, run it first); (2) no menu bar: frame gets WM_NCPAINT but its default handling never reaches the kernel arm and WM_NCCALCSIZE goes only to the edit child (KI-0615, lane `B3550-frame-nccalcsize-and-ncpaint-reach-bar` running at hand-off); (3) KI-0610 native InvalidateWindow probe surface, KI-0614 SetMenu frame change, KI-0617..0623 heap follow-ups, KI-0603 caret blink test red on main, KI-0613 three test targets do not compile, KI-0616 setpriority flake.

## Integration recipe (unchanged; see auto-memory `union-merge-damage-checklist`)

Squash the lane to one commit (`git reset --soft $(git merge-base HEAD origin/main)`), rebase once; ledger conflict → `git checkout origin/main -- scratch/known_issues.md scratch/archive/fixed-issues.md`, re-add the lane's rows with `/home/nd/oxide/tgt-B3525/readd.py`, `--fix` again; `raw_args.rs`/tests conflicts → `union.py`, `sortraw.py`, `dedupetest.py`, `mergeasserts.py`; then hosted suites + `make windows-surface-gate` + BOTH `xtask kernel --arch … --check` (the only gates compiling target-gated files); push with the five SKIP flags (KI-0287/0318/0423/0319/0019) + SKIP_SMOKE; PR; merge; remove worktree. Acceptance: run DETACHED (`setsid nohup` a script that sets `OXIDE_NOTEPAD_ACCEPTANCE_DIR=/home/nd/oxide/accN` and runs `./tools/windows-notepad-acceptance.py`, then touch a DONE file; see `/home/nd/oxide/acc8/run.sh`) because the session's low-memory guard kills foreground/background runs during image assembly (page cache, not real pressure); visible QEMU window, do not close it. `native_process_identity` fails on any reused target dir (three sched rlibs), not a regression.

## Open follow-ups worth a lane

KI-0522 clipboard delay render, KI-0523 hooks not consulted by message paths, KI-0524 class keyed by name, KI-0530/0532 display config + single device, KI-0541..0545 drag/idle details, KI-0520 block test workspace-only failure, KI-0355/0356/0359 FIXED rows never archived (`issues.sh --check` noise). Then: Wine's own user32/gdi32 conformance executables under the launcher as the semantic gate.
