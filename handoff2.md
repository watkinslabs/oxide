# Handoff — input/display fixes plus checked frame ACKs; visual acceptance open

First command: `git status --short`
Worktree /home/nd/oxide/kernel-B3630; branch B3630-paint-region-collapse.
Read CLAUDE.md. Main read-only afa38ce09. Draft PR7680.
Goal: defect-free Notepad buttons/borders/Open/Save/menus/About; not complete.
User requests visible boot when ready, inspection VM left running.
No live QEMU. Latest final-verification boot Sept9 22:32:39UTC stalled before
GNOME desktop appeared; user closed it because startup took too long.
Launcher exited status0 at22:36:26UTC. No Notepad launched or menus clicked.
Artifacts target/B3630-display-verification-debug; UART
 target/boot-logs/x86_64-20260909-223239.log. Kernel10b1ae09f staging, explicit
Wine11.16-debug; compositor SHA9d2d07c8452d9035c73f44edf9dab9fc00caa54de5aa8c2310b8c04e884f6a3e.
GNOME387 snapshot /tmp/B3630-display-guest-threads.json: syscall202 private
wait expected2; poll wchan stale. KI0901 fixed9afaf5491: futex wait paths previously failed to
refresh park_site. Repair records all five sleep publications;68 core,
102 PI and1529 IPC library tests pass. Both builds/features/frame gates pass;
static336x86/278ARM primary rows unchanged; KI0019 failures remain.
Repair is diagnostic, not a proven KI0865 stall fix.
SSH DisplayConfig query did not reach guest (connection refused after exit).
Empty stack strings came from uid1000 reads; proc stack requires SYS_ADMIN.
Next capture: privileged per-thread stack reads, record credentials first.
Do not infer an unwinder defect from these unprivileged empty results.
Consult local pinned primary sources first; Wine11.16 release/debug explicit.

## Current work

- KI0903 runtime13f9a59e9: SB_CTL uses existing control-owned flags and
  EnableWindow state helper; no ShowWindow on enable.21 boundary tests PASS,
  restored ShowWindow regression RED. Fixture uses canonical show to preserve
  WS_VISIBLE. Full callbacks/accessibility KI0904; control raster KI0885.
  scratch/B3630-scroll-enable-validation.md. Both builds/features PASS;
  final-source build/frame/stack validation ongoing; not yet pushed.
- KI0865 claimed8b4a842f2. Harness now captures reader credentials plus desktop
  process/thread status,syscall,wchan,stack during the real frame wait after30s.
  Command bounded10s; UART retains read errors/status. No debugger attachment.
  Launch/poll hook removals fail tests;51 Notepad Python tests PASS.
  scratch/B3630-desktop-capture-validation.md. No new boot/root-cause claim.

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
  unhandled cases include sizegrip cursor/click, SBM state messages, keyboard,
  pointer tracking, focus/caret and accessibility. Primary procedure reviewed.
  Use existing scroll state/position/Send owners; full dialog acceptance stays
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

## Last preview — failed

- Sept9 16:39:27UTC; QEMU1055258/launcher1055198 exited16:41:20UTC,status0.
  No quit/shutdown sent. Exit cause unknown; no automatic relaunch for exit.
- target/B3630-click-preview-debug/live.json, audit-live.md, screenshots
  notepad-ready.png/after-dialog-button.png. UART
  target/boot-logs/x86_64-20260909-163927.log.
- Blank About-like dialog/button, stale surfaces/trails; controlledclick713,397
  did not verify down/up dispatch. File→Open acceptance not completed.
  Audit FAIL29 distinct bridge-refusals position7/visibility6/destroy2.
- Preview kernel SHAee24bfab8d6385ca0de7af5c6fd757f9252122c08bc66bb5ada2a41a06cd243c.
  Wine11.16-debug source/staged stamps matched.
- /tmp/B3630-click-preview.py prepare|run and /tmp/B3630-qmp-action.py
  status|screen LABEL|click X Y WIDTH HEIGHT|keys QCODE... preserve VM.
  Never terminate user inspection VM. Boot only when final acceptance ready.

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
