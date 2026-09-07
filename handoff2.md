# Notepad: surface closed by gate, not by boots — 2026-09-07

First command: `git log --oneline -8 && make windows-surface-gate && cat target/windows-surface-audit.md | head -40 && git worktree list`

## State (main 6060dbf2e + whatever the family lanes merged)

Notepad boots, loads imm32 at runtime, creates/shows its three windows, paints, and runs its message loop (uart-1263402). Merged today (PRs #7521-#7535): NT free tears down page tables (KI-0436); callback continuations preserve the full entry frame + callee-saved FP (KI-0440); hardware exceptions dispatch to KiUserExceptionDispatcher and a refused delivery terminates (KI-0437/0469); builtin classes with cursors + InitBuiltinClasses callback (KI-0434); CreateBitmap/PatternBrush/OpenDCW/GetDeviceCaps; delay-load resolver (KI-0442) with the reference's signed thunk index; DOS drive mapping + default DLL load path + forwarder-chasing runtime resolver (KI-0480); 16550 transmit-edge stall (serial silence); acceptance harness: title-located token check, overview escape + window activation; static call-surface gate.

## The rule that now governs the campaign

`make windows-surface-gate` (`crates/kernel/syscalls/tests/windows_call_surface/`, ~1.4 s) enumerates every win32u ordinal, ntdll export and import binding of Notepad's 27-module closure from the shipped Wine DLLs and ratchets against `baseline.txt`. Baseline at C1558 merge: 313 unadmitted win32u ordinals (129 gdi32, 176 user32, 8 imm32), 10 ntdll names, 10 unbindable imports. Work is fanned out per Wine source file, implemented from the reference bodies with hosted tests, baseline shrunk with `make windows-surface-gate-update`, then ONE acceptance boot. Never discover gaps by boot again (user rule; see auto-memory `windows-surface-from-wine-source`).

## Lanes in flight at hand-off (check `git worktree list`; each is unpushed, integration owner merges)

| Branch | Family |
|---|---|
| F1610-gdi-paths-regions-clipping | path.c, region.c, clipping.c |
| F1611-gdi-bitmaps-dib-blit-palette | bitmap.c, dib.c, bitblt.c, palette.c, brush.c |
| F1612-gdi-fonts-text-ordinals | font.c |
| F1613-gdi-dc-state-transform-draw-print | dc.c, mapping.c, painting.c, printdrv.c, opengl.c |
| F1614-user-input-cursor-rawinput | input.c, cursoricon.c, rawinput.c |
| F1615-user-window-desktop-clipboard-hook | window.c, winstation.c, clipboard.c, hook.c |
| F1616-user-message-timer-scroll-menu-sysparams | message.c, scroll.c, menu.c, dce.c, sysparams.c |
| F1617-ntdll-ip-strings-md4 | ntdll rtl.c IPv4/6 strings, MD4 |
| C1559-acceptance-audits-uart-findings | harness fails on any UART finding (RAW-UNCLAIMED, LDR-FAIL, DELAYLOAD-FAIL, ...) |

Integration per lane: rebase onto main; ledger conflicts → take main's ledger + archive, re-add the lane's genuinely new OPEN rows with fresh ids, re-`--fix` (ids collide across lanes; helper `/home/nd/oxide/tgt-B3525/readd.py`); `raw_args.rs`/`dispatch.rs`/`baseline.txt` conflicts → take main and re-apply the lane's additions, then `make windows-surface-gate-update`; hosted tests + both-arch `xtask kernel --check`; smoke only for boot-visible changes; one acceptance boot after the wave (`OXIDE_NOTEPAD_ACCEPTANCE_DIR=<short path>`; needs `target/lanes` symlink; QEMU window is visible — tell the user not to close it).

## Open after the wave

- KI-0473 (noncontinuable RaiseException from DelayLoadFailureHook resumes the raiser) — exception second-chance path.
- KI-0470 exit status truncation; KI-0475 ext4 has no case-insensitive lookup; KI-0474 acceptance headless mode; 31x spec gap (R lane); KI-0478/0479 IME default window + driver hooks; KI-0438 page-per-alloc heap (perf).
- Semantic layer: build/run Wine's own user32/gdi32/ntdll conformance test executables under the launcher (next gate after the surface reads zero).
