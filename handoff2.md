# Notepad acceptance PASSES on oxide — 2026-09-07

First command: `git log --oneline -8 && make windows-surface-gate && tools/issues.sh --query status=OPEN sev=high`

## State (main 579c042e5)

`./tools/windows-notepad-acceptance.py` reports **PASS**: A1/A2/A3 (PE load, window, present, typed token painted) and A4/A5 (close, exit status 0, wrapper cleanup), with `notepad-uart-audit: PASS` (no unclaimed or refused Windows call). Evidence: `/home/nd/oxide/acc13/` (screenshot shows the menu bar, the token on line 1, `Ln 1, Col 14`). Static surface: `crates/kernel/syscalls/tests/windows_call_surface/baseline.txt` has zero entries. Notepad loads from the shipped Wine PE DLLs against the kernel's own NT/win32u/wineserver semantics; there is no Wine unix side.

Run acceptance DETACHED (`setsid nohup` a script that sets `OXIDE_NOTEPAD_ACCEPTANCE_DIR=/home/nd/oxide/accN` and touches a DONE file; template `/home/nd/oxide/acc8/run.sh`): the session's memory guard kills long foreground runs during image assembly. The QEMU window is visible; typing into it during a run changes what the harness sees.

## What the campaign closed (46 merged PRs, #7536-#7590)

Linux-side causes behind "Windows" symptoms: cpufreq hook spinning on a process-held lock inside the wakeup IRQ (the "serial stall"); `shmctl` answering EIDRM for SHM_DEST segments, which killed `mutter-x11-frames` through MIT-SHM and hid the window; NT heap mapping a page per allocation. Windows layer: one routing chain for both win32u entries (the raw path had refused twelve families), retrieval-time hardware ladder, one InvalidateRect owner, PE resource walk (root-relative offsets + language fallback, so LoadMenu works), creation-time WM_NCCALCSIZE and complete class info, menu item strings, kernel-owned text runs, menu bar paint and tracking loop, damage cropped to the visible rect, client rect carried with the window, caret drawn instead of transacted, per-paint damage instead of whole-window presents.

## Instrument lessons (cost hours; do not repeat)

The harness lied five times: truncated oops capture, a console reader that stopped at the last marker and later dropped its tail, an overview detector that could never fire, a fixed post-typing wait, and a window rect projected from the centred title. Three "kernel wedges" and two "no input" readings were those artifacts. The per-syscall console trace itself starved the message pump. Before believing a boot symptom, rule out the capture.

## Open work

`tools/issues.sh --query status=OPEN` — highest value first: KI-0649 present floor (~0.18 s per present: EndPaint bypasses the flush pump that already exists; lane running at hand-off), KI-0644 ~860 kernel entries per typed character, KI-0632 item-info method slots, KI-0637 menu font, KI-0638 mnemonic underline, KI-0641 configure runs no NCCALCSIZE, KI-0613 five test targets do not compile, KI-0616/KI-0653 parallel-suite flakes, KI-0647 intermittent early-boot halt in rq_locate. Next gate after those: build and run Wine's own user32/gdi32/ntdll conformance executables under the launcher.
