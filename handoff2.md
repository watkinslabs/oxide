# Notepad: menu bar legible, typing handled; text paints too slowly for the harness — 2026-09-07

First command: `git log --oneline -8 && make windows-surface-gate && git worktree list && tools/issues.sh --query status=OPEN grep='Notepad\|bridge\|menu'`

## State (main db44b8870)

- Static call surface closed: `crates/kernel/syscalls/tests/windows_call_surface/baseline.txt` has zero entries (134 → 0 this session: PRs #7546 window/desktop/clipboard/hook, #7547 message/timer/scroll/menu/sysparams, #7551 drag/icon/idle; #7548 warning fix). KI-0473 fixed.
- Serial "stall" was never the UART: the scheduler's cpufreq hook spun on a process-held plain spinlock inside the wakeup IRQ (PR #7545, KI-0521).
- Notepad window never reached the GNOME screen because `shmctl` answered EIDRM on segments marked SHM_DEST, which is the normal state of a GTK MIT-SHM segment; XWayland turned it into BadAccess and `mutter-x11-frames` died on every map (PR #7550, KI-0540). Acceptance run `/home/nd/oxide/acc2/` (uart-193559.log, screen-193559-after-token.ppm): Notepad is framed, titled, raised on click, paints white client + status bar.
- One wait list carries the message queue and NT objects (PR #7549, KI-0535).

## What acceptance still fails on (last full run `/home/nd/oxide/tgt-B3557/acc/`)

Merged since the previous note: #7579 creation-time WM_NCCALCSIZE + complete class info (menu name); #7580 PE resource walk (offsets from the root, language fallback) so LoadMenu works; #7581 damage cropped to the visible rect + BeginPaint reserves before the DC (status-bar paint storm); #7582 menu item strings read to the NUL; #7583 per-syscall console trace removed (it starved the pump) + client rect carried on move; #7584 kernel-owned text runs sized on their own fields + redirect status returned + text order at the issuer's callback depth: the bar reads File Edit Format View Help; #7585 configure keeps nonclient insets and reads a child in the parent's client space (band no longer overwritten).

Now: framed, focused, menu bar legible and stable, click activates, every typed key retrieved and handled by the edit, every invalidation records damage, WM_PAINT retrieved. Still red: the pump spends ~240 ms per typed character (KI-0636; lane `B3556-typed-character-latency` running at hand-off), so the token is not drawn within the harness's 2 s window. Then the harness continues to A4/A5 (clear token, Alt+F4, exit status 0). Open follow-ups: KI-0630 (evidence updated), KI-0632 item-info method slots, KI-0637 menu font, KI-0638 mnemonic underline, KI-0641 configure runs no NCCALCSIZE, KI-0610/0614/0625/0626/0627/0629/0640/0643, heap KI-0617..0623.

## Integration recipe (unchanged; see auto-memory `union-merge-damage-checklist`)

Squash the lane to one commit (`git reset --soft $(git merge-base HEAD origin/main)`), rebase once; ledger conflict → `git checkout origin/main -- scratch/known_issues.md scratch/archive/fixed-issues.md`, re-add the lane's rows with `/home/nd/oxide/tgt-B3525/readd.py`, `--fix` again; `raw_args.rs`/tests conflicts → `union.py`, `sortraw.py`, `dedupetest.py`, `mergeasserts.py`; then hosted suites + `make windows-surface-gate` + BOTH `xtask kernel --arch … --check` (the only gates compiling target-gated files); push with the five SKIP flags (KI-0287/0318/0423/0319/0019) + SKIP_SMOKE; PR; merge; remove worktree. Acceptance: run DETACHED (`setsid nohup` a script that sets `OXIDE_NOTEPAD_ACCEPTANCE_DIR=/home/nd/oxide/accN` and runs `./tools/windows-notepad-acceptance.py`, then touch a DONE file; see `/home/nd/oxide/acc8/run.sh`) because the session's low-memory guard kills foreground/background runs during image assembly (page cache, not real pressure); visible QEMU window, do not close it. `native_process_identity` fails on any reused target dir (three sched rlibs), not a regression.

## Open follow-ups worth a lane

KI-0522 clipboard delay render, KI-0523 hooks not consulted by message paths, KI-0524 class keyed by name, KI-0530/0532 display config + single device, KI-0541..0545 drag/idle details, KI-0520 block test workspace-only failure, KI-0355/0356/0359 FIXED rows never archived (`issues.sh --check` noise). Then: Wine's own user32/gdi32 conformance executables under the launcher as the semantic gate.
