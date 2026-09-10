# Handoff — input/display fixes plus checked frame ACKs; visual acceptance open

First command: `git status --short`
Worktree /home/nd/oxide/kernel-B3630; branch B3630-paint-region-collapse.
Read CLAUDE.md. Main read-only afa38ce09. Draft PR7680.
Goal: defect-free Notepad buttons/borders/Open/Save/menus/About; not complete.
User requests visible boot when ready, inspection VM left running.
No live QEMU. Latest verification Sept10 01:09:04-01:12:20UTC reached GNOME
and Notepad; About shows blank captions and horizontal stripes outside dialog.
Exit0; no quit sent, exit cause unconfirmed. Artifacts
 target/B3630-sizegrip-verification-debug; UART uart-2337193.log.
Automated helper failed initial-token with About already open; no automated
File/Open/Save check ran. Do not report menu acceptance. Kernel SHA
 fd1c550d91647e63988ac4b4c57d9d1efb1a6350e560b385905e86a55c555239;
Wine11.16-debug stamp000982e8e976863f0a29925ab7426d09808a3e61c125c18decc4cf77f27af5da.
Compositor9d2d07c8452d9035c73f44edf9dab9fc00caa54de5aa8c2310b8c04e884f6a3e.
Caption repair: shared text snapshots admit and carry MM_TEXT translation;
native request maps run and active rectangle before callback. Actual binding
regression RED Codec; real renderer pixel test GREEN and missing translation
control RED.76 native GDI tests pass. KI0906 underline repaired6afc8cf2a. Both builds/features/frame gates PASS;
static336/278 no added/increased path. KI0019 failures remain. scratch/B3630-caption-origin-validation.md. Two Frame refusals
HWND10000e seq216/221 InvalidCommand; stripe cause unproved.
Prior Sept9 22:32 verification stalled before GNOME; user closed that VM.
KI0901 repaired stale futex park_site diagnostics9afaf5491, not proven GNOME
stall fix. Privileged capture wired below; foreign proc maps still KI0905.
Consult local pinned primary sources first; Wine11.16 release/debug explicit.

## Current work

- Caption text124db9405, underline6afc8cf2a; audit4afe6e193 detects twelve
  measured text refusals in retained run.52 Python tests PASS;76 native GDI,
  8 pen boundary,1532 IPC tests PASS. Text and pen translation removals RED.
  ELFs target/B3630-caption-final-{x86_64,aarch64}.elf; full evidence
  scratch/B3630-caption-origin-validation.md. No new VM after failed run.
- Compositor refusal diagnostics plus opt-in X pixel readback;107 tests PASS.
  Enable harness OXIDE_NOTEPAD_READBACK=1. Both release builds PASS; evidence
  scratch/B3630-readback-validation.md. Stripe mechanism remains unproved.

- Refresh/keyboard a5c29407a; focus + gray/signed carets now56 scroll/10 caret
  tests PASS; adjacent44/9/29 PASS. Both builds/features/frame gates PASS;
  static335/278 no growth. scratch/B3630-caret-focus-validation.md. Custom
  bitmap masks KI0398; pointer/setters/accessibility KI0885 still open.
- KI0903 runtime13f9a59e9: control-owned arrow state and EnableWindow state
  helper preserve visibility. Closed after source37f740be7 validation.
- KI0885 sizegrip input4ad3d553a: cursor preserves previous handle; click
  sends canonical parent SC_SIZE with RTL edge and resumes0.26 actual control
  boundary tests PASS; missing cursor/click and old ShowWindow controls RED.
- Final source37f740be7 both builds/features/frame gates PASS; static336x86/
  278ARM rows unchanged, no added/increased path versus parent-handling.
  Existing KI0019 failures/exception7664+6368 remain. info query storage kept
  off shared Show router frame; deepest x86 route14792->14744. Enable-only
  separation failed and was removed. Final logs /tmp/B3630-sizegrip-final-*;
  snapshots target/B3630-sizegrip-final-{x86_64,aarch64}.elf. Evidence
  scratch/B3630-sizegrip-validation.md and B3630-scroll-enable-validation.md.
- KI0865 claimed8b4a842f2; captured73b21c9f: desktop wait sends reader
  credentials and desktop process/thread status,syscall,wchan,stack after30s.
  Command bounded10s; read errors/status retained in UART.51 Notepad Python
  tests PASS; launch/poll hook removals RED. No debugger attachment.
- KI0913/KI0915 validated runtime94522894c: scratch/B3630-paint-status-validation.md;1557 IPC/145 dispatch/35 wait/70 send/3276 library PASS;14 controls RED. Both release/features/frame PASS; static baseline335/278 unchanged, no growth. KI0914 Peek flags, KI0712 wait flags, KI0912 objects, KI0844 stride, KI0916 direct input status remain; desktop acceptance outstanding. KI0914 removal repair: scratch/B3630-peek-flags-validation.md;147 dispatcher PASS; both target checks PASS; class selection implemented,1559 IPC/3276 library/149 dispatcher PASS;3 class controls RED. Both release/features/frame PASS; static335/278 unchanged, no growth. Fresh debug image prepare76901 running; /tmp/B3630-queue-verification.py prepare|run; no VM yet. KI0917 quit filtering remains.
- Next visible verification helper /tmp/B3630-sizegrip-verification.py
  prepare|run; id B3630-sizegrip-verification-debug, Wine11.16-debug,
  token oxide-b3630-verify. Latest run failed as above; no automatic reboot.
  Helper only launches/activates; separate UI checker failed before DialogChecks.
- Full control behavior/EnableWindow KI0885/KI0904 remain; raw static harness KI0574 still
  fails its stale source needle. Foreign maps omit file identity/offsets/
  paths (newKI0905); captured user PCs cannot yet be assigned to ELF symbols.

- KI0890 runtimee3a491288 committed: parent Send continuation, nonzero parent
  result preserved; caption left-down MA_NOACTIVATE, others MA_ACTIVATE.
  IPC owns policy; canonical relative_parent handles combined child/popup
  ownership.128 dispatcher tests at this point; evidence
  scratch/B3630-mouse-activation-validation.md. KI0890 closed after validation.
- KI0462 cursor parent-first runtimeca1c3c77f committed/closed: raw default selector
  routes through DefaultProc; exact desktop and resize borders bypass parent;
  accepted parent returns1; otherwise apply cursor and return0. Existing Send
  continuation retains full class HWND/OEM step without another queue.
 139 dispatcher/cursor tests and3270 syscall library tests pass. Sound intent
  retained but actual MessageBeep absent (newKI0902). Evidence
  scratch/B3630-cursor-parent-validation.md. Raw selector source audited;
  dispatcher fixture does not independently execute raw selector.
- Final parent-handling builds/features/both frame gates PASS;
  static336x86/278ARM primary rows unchanged, no added/increased path versus
  futex-site baseline. KI0019 failures/7664+6368 exceptions remain.
  /tmp/B3630-parent-handling-final-{build,feature}.log;
  parent-handling-{frame,stack}-{x86,arm}.log and stack-compare.log.
  ELFs target/B3630-parent-handling-{x86_64,aarch64}.elf; hashes in evidence.
- Next work: KI0885 full scrollbar procedure (control_proc/proc_abi). Existing
  unhandled cases include SBM setter messages,
  pointer tracking and accessibility. Focus/caret source repaired; masks tracked.
  Next: KI0904 EnableWindow callbacks; then setters/tracking. Acceptance stays
  required. No new boot until final verification; prepare privileged thread
  stack capture for GNOME stall evidence before that next verification.

- Pushed/remote-verified c11e7ea62: display stacking runtimea7d181ac3,
  KI-0897 closed. Backend sibling insertion means preceding HWND: BELOW,
  not ABOVE. Decorated top-level BadMatch forwards original ConfigureRequest
  to root manager; other X errors remain failures. Real Xvfb red/green and
  BadWindow-swallowing positive control. Backend diagnostics retain
  sequence/HWND/error plus restack target/sibling/mode/error.
  scratch/B3630-display-stacking-validation.md;100 compositor tests passed.
  Both compositor/kernel release builds passed. Push180 hosted + both features
  passed with only documented KI0019 lint/test-build/stack exceptions.
- Runtime0d529870e fixes KI0898/0899; both closed after validation.
  Teardown/Showa79f4d8e8 pushed and remote-verified; stackingc11e7ea62 too.
- KI-0898: destruction_order is callback preorder. Ordinary Destroy/default
  Close and raw lifecycle cleanup now reverse only publication cleanup, so
  parent X Destroy cannot invalidate later descendant requests. Callback
  order unchanged; thread-exit already dependent-first, unchanged.
  Actual dispatcher regressions Destroy/default Close fail before correction,
  pass after; raw lifecycle wrapper reviewed but not independently executed
  by this fixture.123 dispatcher tests PASS.3270 syscall-library tests PASS.
- KI-0899: Show previously replayed whole surface after map, rejecting valid
  partial coverage. It now replays exact existing areas through immutable
  repaint. Real Xvfb checks disjoint painted pixels plus untouched background;
  removing replay fails pixels even though Show succeeds.101 compositor tests
  PASS. No second coverage owner, no full-surface copy.
- Evidence scratch/B3630-display-teardown-show-validation.md.
  /tmp/B3630-teardown-{order-red,default-red,final-dispatch,syscalls-lib}.log.
  /tmp/B3630-partial-show-{red,replay-control,final-tests}.log.
- Both kernel/compositor release builds and both features PASS; both frame
  gates PASS. Static primary336x86/278ARM rows have no added/increased path
  vs scope baseline; existing KI0019 failures and7664/6368 exceptions remain.
  /tmp/B3630-teardown-show-build.log, teardown-feature.log,
  teardown-{stack,frame}-{x86,arm}.log, teardown-stack-compare.log.
  Final ELFs target/B3630-display-final-{x86,arm}.elf and compositor-release
  binaries saved; hashes in teardown/Show evidence. Push180 hosted/both
  features PASS; only documented KI0019 baseline exceptions used.
- KI0900 fixed0314a2e42, validated/closed; f9b73e77e remote-verified. All image
  tiles submit checked X11 requests before batch completion. Every result
  checked before ACK; errors log HWND/X11 sequence/resource/code/opcodes.
  Actual protocol regression fails before fix (ACK0 instead of1). Checking
  only last cookie fails earlier-error regression.103 compositor tests PASS,
  both compositor release builds PASS. Kernel unchanged since teardown.
  Push180 hosted/both features PASS with documented KI0019 exceptions.
  scratch/B3630-checked-frame-validation.md; /tmp/B3630-draw-*.log.
  Latest artifacts target/B3630-compositor-checked-release-{x86,arm}; use
  these instead of prior compositor-release snapshots on next staging.
- Next runtime acceptance must distinguish repaired refusal classes from
  unexplained residual visual defects. Prior UART alone does not attribute
  all29 refusals. Full scrollbar KI0885 and activation/cursor policies open.

## Avoid stale diagnoses

- KI-0861 historical750x1 is superseded by actual Open run
  target/boot-logs/x86_64-20260909-143112.log: parent100005/custom10001c
  retain750x484. Do not restart old collapsed-client investigation.
- That run's toolbar invalid geometry predates control traversal322669c2a;
  missing GetDlgItem results leave layout RECTs unwritten. Full layout
  acceptance still outstanding; no new size clamp is justified.
- KI-0895 CLOSED disproven: bridge::window only parses HWND, never queries
  canonical state. Publishing Destroy after removal already works. The real
  KI0898 defect is parent-before-child publication, not absent HWND lookup.
  scratch/B3630-destroy-publication-audit.md;7f400aa52/51601b1ec.

## Existing input repairs

- Hardware runtime8fedf4646/249d43553/276390dfd/3e69d8755 preserves raw queued
  messages, returns transient Box<Selected> views to real dispatcher, retires
  by stable ID and stamps GetMessagePos from event screen coordinates.
  c9834ba26 helper reverted06dcd177c for stack growth; never restore it.
- KI0682/KI0892/KI0893/KI0894/KI0896 closed. Scope runtimea165b0c85,
  filter runtimeee58ef0b7. Native child surfaces queue top-level scope;
  allocation-free first-child walk selects receiver thread separately from
  retrieval hit testing. Transparent candidates continue through callbacks;
  exhausted popup may try immediately following same-thread owner once.
- Filters retain excluded raw events and continue scanning with stable IDs;
  posted fallback excludes hardware, scan watermark prevents GetMessage spin.
  debug-winpump HIT/VIEW/FILTER traces correlate event identity and delivery.
-1529 IPC,3270 syscall-library,24 actual-driver,121 prior dispatcher tests
  passed; newest teardown fixture increases dispatcher count to123.
  Fixtures use hosted task/clock/Send/usercopy seams, not full real User32.
  scratch/B3630-native-pointer-scope-validation.md,
  scratch/B3630-hardware-filter-validation.md.
- Scope stack baseline /tmp/B3630-scope-stack-{x86,arm}.log:336/278 primary
  rows including exception, no new/increased path vs filter baseline.
  Exception7664/6368 unchanged. KI0019 baseline failures remain; never call
  full gate green. Compare primary rows before "Split the chain", not top20.
  Final ELFs target/B3630-scope-final-{x86,arm}.elf; hashes in scope evidence.

## Open scope and companion repositories

- KI0887 parent-DC IncludeInferiors repaired0190b0530; real Xvfb97 tests
  passed. Full blank captions/trails/stale-menu visual acceptance still open.
- KI0885 scrollbar CREATE/PAINT/ERASE/GETDLGCODE + callback8 record104bytes
  repairedc39326127/a66384dcb. Full mouse/key tracking, focus/caret,
  accessibility,sizegrip/visibility and raw callback boundary incomplete.
  SCROLL-PROC-UNHANDLED/SCROLL-PAINT-FAIL rejected by UART audit.
- KI0890 mouse activation parent/caption; KI0462 parent-first cursor;
  KI0504 thread-input focus/capture ownership; KI0604 full input/menu tests.
  ARM callback continuations KI0699/KI0703/KI0704 remain open.
- Full Notepad KI0859/0860/0861/0862/0863/0865 open. Durable full evidence
  scratch/B3630-notepad-verification.md. Keep PR draft.
- packages B3630-wine-profiles6830f27; images B3630-wine-profiles553217b.
  Both local commits, no remotes; preserve images .dist-old-layout/.
  OXIDE_WINE_PROFILE=release|debug independent of kernel PROFILE; docs39§13.
  ARM compositor builds use existing target/B3630-arm-sysroot completed from
  cached Fedora RPMs. System sysroot unchanged; KI0421/KI0691 apply there.
- PR body /tmp/B3630-pr-body.md. Explicit git add; no fmt/stash/reset/amend.
  Push uses only proven KI0019 SKIP_LINT_RATCHET, SKIP_TEST_BUILD_GATE,
  SKIP_STACK_GATE; never skip hosted/features or admit new stack growth.
