# Handoff — preview failed visually; dispatcher walk missing

First command: `cat target/B3630-click-preview-debug/live.json`

Worktree /home/nd/oxide/kernel-B3630; branch B3630-paint-region-collapse.
Main read-only. Read CLAUDE.md. Draft PR7680; last pushed6e5ece2fd; local implementationc39326127.
Goal: defect-free Notepad borders/buttons/Open/Save/dropdowns/About, with
actual visible acceptance. User requests boot when ready and VM left running.
Consult pinned local sources first; Wine11.16, never host Wine fallback.

## Live VM

- Preview1055195 booted16:39:27UTC; Notepad activated. QEMU1055258 and
  launcher1055198 exited16:41:20UTC, launcher status0. No shutdown/quit sent.
  No live QEMU now. User asked asynchronously whether they closed the window;
  answer pending. Status0 alone does not prove why it exited.
- target/B3630-click-preview-debug/live.json contains sockets/logs and later
  launcher exit status. Never kill inspection VM or treat stale sockets as live.
- /tmp/B3630-click-preview-live.log reports activation/readiness/failure.
  Serial target/boot-logs/x86_64-20260909-163927.log.
- /tmp/B3630-click-preview.py run launches/activates Notepad, keeps UART logging,
  waits for natural launcher exit; no automatic powerdown or termination.
- /tmp/B3630-qmp-action.py status; screen LABEL; click X Y WIDTH HEIGHT;
  keys QCODE... . Records actions in preview manual-commands.jsonl.
- File→Open acceptance NOT completed. Screenshot already showed blank dialog
  and later Wine License. One controlled click713,397; no verified down/up.
  Exit prevented subsequent Escape. Must verify actual File→Open/buttons.
  QMP input acceptance alone is not guest dispatch success.
- Preview Wine profile debug verified against composed source and staged root.
  Kernel SHA256 ee24bfab8d6385ca0de7af5c6fd757f9252122c08bc66bb5ada2a41a06cd243c.
  Features debug-winpump,debug-winframe,debug-wingeom. Fresh root staged;
  final kernel refreshed after cleanup fix. No old artifact fallback.

## Uncommitted implementation (KI0885)

- Raw scrollbar selector029a routes CREATE/PAINT/ERASE/GETDLGCODE and delegates
  default messages. Remaining known messages emit SCROLL-PROC-UNHANDLED and
  explicit failure. Full scrollbar procedure remains unfinished; do not close.
- Canonical HWND control storage initialized from CREATESTRUCT disabled style.
  Creation alignment handles orientation, sizebox/grip and edge anchoring.
- Typed nt_user_callback Input::User/Record; record copy below saved RSP,
  checked alignment/bounds/write failure before callback frame admission.
  Drawing callback8 takes104-byte record; pinned-header layout checked both
  architectures in /tmp/B3630-scroll-callback-layout.c and object files.
- Existing AMD64 continuation retained. ARM continuation remains unsupported
  (KI0699); now reports USER-CALLBACK-REJECT with input metadata.
- Control paint uses existing preparation queue then external callback lease
  through EndPaint. Hold validates exact session and owner. Foreign destruction
  keeps leased DC until return; wrong-thread/token cannot release it.
- Paint-open failure cleanup uses existing paintlease::remove_for_current,
  avoiding full dispatcher reentry. Initial version added15184-byte x86 path;
  direct owner call removed that regression. No stack gate weakening.
- Audit rejects unhandled scrollbar messages and failed drawing callbacks.
- Missing: actual raw control/callback boundary fixture; full mouse/keyboard
  tracking, focus/caret, control scroll-info/accessibility, sizegrip cursor/resize,
  visibility/drawable semantics. Pure callback and ownership tests aren't full
  production-callback coverage. Tracking fields currently inactive zeros.

## Validation

-3270 syscall lib,116 actual dispatcher fixture,1523 IPC lib pass.
-33 dialog/QMP/UART-audit tests pass, including21 UART-audit tests.
- Positive controls fail on removed callback record copy, released active DC,
  shifted callback field, substituted creation style; all code restored.
  Creation first attempt was compiler-red; corrected mutation failed assertion.
- Both release builds and both feature checks pass on final code.
- Final stack reports match previous358x86/299ARM rows; no new/increased path.
  Existing KI0019 failures persist:336/277 over-budget paths,7664/6368 exception.
- Logs /tmp/B3630-scroll-procedure-{final-tests,ipc,feature,build,stack-x86,stack-arm}.log.
  Positive controls /tmp/B3630-scroll-procedure-{frame,lease,abi,creation}-red.log.
  /tmp/B3630-compare-stacks.py verifies reports vs scroll-policy baseline.
- Release x86 ELF preserved target/B3630-release-stack-x86.elf SHA256
  82be120b948019627f641cfe9f8bf3c0c1e441f82d7d02f0f67fd556ea45e8ed.
  Image preparation uses shared Cargo target, so preview features replace
  default x86 output after release validation. Keep evidence tied to ELF.
- Implementation committedc39326127. Push first failed hosted unused exports;
  kernel-only reexport cfg fixes it.180 isolated hosted crates and6 callback
  tests pass after repair. Kernel code unchanged by that cfg-only repair.
  Explicit stage paths; no stash/formatters.
  Before push use only documented KI0019 bypasses after baseline proof:
  SKIP_LINT_RATCHET, SKIP_TEST_BUILD_GATE, SKIP_STACK_GATE. No new increases.

## Prior repairs and remaining findings

- KI0886 fixed53cf05cdf: default child hit test now canonical screen rectangle.
  Old VM click655,463 reached button100007, returned HTNOWHERE0 and dropped
  down/up. Real dispatcher regression restored old hook fails0vs1.
- KI0887 IN-PROGRESS: parent-DC X11 clipping fixed0190b0530 IncludeInferiors;
  real Xvfb RED/GREEN and97 compositor tests pass, both builds. Pointer trails,
  stale menus and full visual acceptance remain unproven.
- KI0888/0889 fixedbedf35f86: sole scrollbar arrow flags, zero-page clamp,
  visibility transitions, unchanged redraw and arrow-only refresh. Joined
  fixture uses actual action consumer and worktree modules.
- KI0890 OPEN: default WM_MOUSEACTIVATE lacks parent forwarding/caption rule.
  Ordinary0 still activates in hardware ladder; parent veto/eat semantics absent.
- KI0462 OPEN: default cursor parent-first policy not wired resumably.
  KI0604 broader actual hardware/menu dispatch fixture coverage remains.
- KI0891 OPEN: old detached VM exit provenance missing. Old832847 and launcher
 832789 disappeared with no termination issued here; cause unknown. Preserve
  target/B3630-debug-dialogs logs/screens and serial145749; don't relaunch old VM.
- Existing full Notepad defectsKI0859/0860/0861/0862/0863/0865 remain open.
  PR must remain draft until complete visual acceptance.
- Durable evidence scratch/B3630-notepad-verification.md.

## Wine profiles / companion repositories

- Wine11.16, OXIDE_WINE_PROFILE=release|debug; independent of kernel PROFILE.
  Named source/build/artifact/catalog/RPM paths, stamps and alias gates.
  Both full Wine builds and named RPMs complete; docs39§13.
- packages branchB3630-wine-profiles6830f27 clean, no remote.
- images branchB3630-wine-profiles553217b, no remote; preserve .dist-old-layout/.

## Immediate next work

- Preview audit FAIL:29 bridge refusal records (position7, show6, destroy2).
  target/B3630-click-preview-debug/{notepad-ready,after-dialog-button}.png
  retain blank text, stale surfaces and pointer trails. audit-live.md retained.
- Source/code check confirms KI0682: hardware/live.rs asks only queued HWND,
  then passes HTTRANSPARENT through decide instead of continuing z-order walk.
  Log100.520+ asks static100028, returns-1, then SETCURSOR; no retarget walk.
  This is a concrete missing dispatcher mechanism; exact cause of the controlled
  click is not yet proven. Claim KI0682 before implementation, add actual path
  coverage including capture, disabled candidates and transparent siblings.
- Current implementation has passed final builds; finalize push before next claim.
  Keep PR draft and preserve all failed preview evidence. Do not restart VM
  just because it exited. No complete Notepad or dispatcher correctness claim.
