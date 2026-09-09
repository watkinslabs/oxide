# Handoff — hardware retrieval repair, verification in progress

First command: `git status --short`
Worktree /home/nd/oxide/kernel-B3630; branch B3630-paint-region-collapse.
Main read-only. Read CLAUDE.md. Draft PR7680; runtime fixes pushed0c9a8101c.
Final hardware/position validation passed. Remote0c9a8101c verified after push.
Goal remains defect-free Notepad buttons/borders/Open/Save/menus/About.
User requests visible boot when ready and VM left running. Do not call done.
Wine11.16 release/debug profiles explicit; consult pinned local sources first.

## Current changes

-829dc62d5 repairs point candidate parent-client coordinates, client clipping
  and window regions (KI-0892);1526 IPC tests, both builds/features passed.
- KI-0682 hardware driver now snapshots canonical scoped candidates, continues
  after HTTRANSPARENT across synchronous/suspended calls, handles disabled
  scopes, skips destroyed candidates and rejects destroyed/foreign targets.
  Capture is resolved again at retrieval. Scope includes its own window last.
- KI-0893 raw queued message survives Peek unchanged; Stage::Prepared returns
  translated view to actual Peek/Get dispatcher. Canonical queue assigns a
  stable selection ID so retirement cannot remove an identical successor.
  Removed obsolete raw-message replacement API. MessageQueue implementation
  extracted into message_queue.rs; root now below500 lines; docs52 updated.
- Hardware processing checks queue origin bits: posted mouse-number messages
  no longer enter hit testing. No parallel queue or HWND registry introduced.
- debug-winpump adds WINDOWS-HARDWARE-HIT and WINDOWS-HARDWARE-VIEW with
  selection ID, source/target HWND, raw screen point, hit and translated view.
- KI-0894 OPEN: application filters run too early on raw numbers/HWND;
  transformed filtered messages are deleted. Needs possible-number prefilter
  and stable scan cursor, then final target/message filter without consumption.
- KI-0682 still IN-PROGRESS: compositor events can name a child as scope;
  real child-surface routing needs audit. Scoped walk cannot search siblings
  outside that scope. Owner-next fallback not implemented. No full claim.
- Actual hardware fixture mocks task/clock/Send boundary but imports production
  driver/context; tests synchronous and suspended callback completion.
  Actual dispatcher fixture separately tests Stage::Prepared consumption.
  These are separate boundary fixtures, not a full raw ABI/real User32 run.

## Current verification

- Local runtime changes:8fedf4646 +249d43553 +276390dfd +3e69d8755.
  c9834ba26 helper experiment reverted06dcd177c after measured stack growth.
  Runtime changes published in0c9a8101c. Never overwrite main.
- Prepared message now Box<Selected>, a temporary handoff, not a queue copy.
  General Stage return fits the old small result; actual delivery helper
  performs usercopy outside GUI ownership. Snapshot lifetime ends at delivery.
-11 hardware-driver and119 dispatcher-fixture tests pass, including callback
  suspend/resume, target destruction, capture changes, repeated client and
  nonclient peeks, stable queue identity, posted-message origin, actual usercopy.
- KI-0896 repaired3e69d8755: pointer post stamped previous self.cursor; now
  the canonical queue receives the event's own screen point. New real IPC test
  fails0vs14418030 before fix;1527 IPC tests and both boundary fixtures pass.
  /tmp/B3630-pointer-position-{red,green,boundary}.log.
-3270 syscall library tests pass. /tmp/B3630-hardware-final-syscalls.log.
- Positive controls raw overwrite, transparent-walk bypass, ignored view hook
  fail assertions; restored. /tmp/B3630-hardware-{raw-view,transparent,view-hook}-red.log.
- Box implementation BOTH builds and feature checks pass (28532/92516).
  /tmp/B3630-hardware-box-{build,feature}.log.
- Box stack reports BOTH architectures have no new/increased primary numeric
  paths vs /tmp/B3630-scroll-procedure-stack-{x86,arm}.log. Primary tables:
  337x86/278ARM entries including exception row (336/277 existing task failures).
  Exception reservations remain7664/6368. Top20 membership changed as Windows
  paths shrank; an execve summary row appearing is NOT a new primary path.
  /tmp/B3630-hardware-box-stack-{x86,arm}.log. Keep full reports, don't hide flags.
- Final position-stamp builds58475 and feature85075 PASS on BOTH arches.
  /tmp/B3630-pointer-position-{build,feature}.log. Final primary stack tables
  337x86/278ARM match baseline identities with no added/increased value;
  /tmp/B3630-pointer-position-stack-{x86,arm}.log. KI-0019 baseline failures remain.
- Exact release ELFs preserved target/B3630-hardware-final-{x86,arm}.elf.
  x86 SHA6fdb203e7d2df7fe4c2c3bce54c41bc66d46c7cd5ee8dfe242f2434f4741d5c1;
  ARM SHA0c9955f3afd6551fad9240c04ea6f2ad69fa10f96fb4ff0e3ab6a99c480fe2c3.
- KI-0892/0893/0896 closed via829dc62d5/8fedf4646/3e69d8755. KI-0682 remains
  open for child-surface scope/owner fallback, KI-0894 for filtering/scanning.
- Earlier initial/refactor stack failures remain evidence, not current results.
  Do not use the abandoned dispatch helper or claim initial stack was baseline.
- KI-0895 was a FALSE hypothesis: bridge::window only parses HWND, does not
  query WindowManager. Destroy publishing already proceeds after teardown.
  No destruction code changed. Closed via7f400aa52/51601b1ec; proof in
  scratch/B3630-destroy-publication-audit.md. Do not revive that diagnosis.
- Worktree refreshed with origin main (already up to date), then reconciliation
  timestamp refreshed; guard passed. No stash, main edits or formatters.

## Last preview — FAILED, no live VM

- Boot16:39:27UTC Sep9, QEMU1055258 and launcher1055198 exited16:41:20UTC,
  launcher status0. No quit/shutdown sent here. User exit clarification pending.
- target/B3630-click-preview-debug/live.json holds sockets/log/start/end/status.
  Serial target/boot-logs/x86_64-20260909-163927.log.
- Notepad activated, blank About-like dialog/button, stale surfaces and trails.
  One controlled click713,397 had no verified button-down/up dispatch.
  File→Open acceptance NOT completed. No automatic VM restart for its exit.
- audit-live.md FAIL:29 bridge-refusal records (position7,show6,destroy2).
  Screens notepad-ready.png and after-dialog-button.png retained beside audit.
- Preview kernel SHA ee24bfab8d6385ca0de7af5c6fd757f9252122c08bc66bb5ada2a41a06cd243c;
  Wine11.16-debug stamps matched source/staged root. Features winpump/frame/geom.
- /tmp/B3630-click-preview.py prepare|run imports harness, activates Notepad,
  logs serial and waits natural launcher exit. Never kills inspection VM.
- /tmp/B3630-qmp-action.py status|screen LABEL|click X Y WIDTH HEIGHT|keys QCODE...
  records commands. No live VM now. Boot only once final gates ready.

## Prior work / open defects

- KI-0886 fixed53cf05cdf: actual default hit-test hook uses screen geometry.
- KI-0887 IN-PROGRESS0190b0530: parent-DC X11 IncludeInferiors; Xvfb red/green,
  97 compositor tests. Trails, stale menus and complete visual repair remain.
- KI-0888/0889 fixedbedf35f86: canonical scrollbar arrow flags, zero-page clamp,
  hide/disable/redraw distinctions and actual action-consumer fixture.
- KI-0885 IN-PROGRESSc39326127/a66384dcb: scrollbar CREATE/PAINT/ERASE/GETDLGCODE,
  typed callback8 record104 bytes, callback DC lease through EndPaint,
  creation style alignment. Remaining control messages emit explicit failure
  with SCROLL-PROC-UNHANDLED; drawing rejection SCROLL-PAINT-FAIL. Audit rejects.
  Missing full mouse/key tracking, focus/caret, accessibility, sizegrip,
  visibility/drawable semantics and actual raw callback-boundary fixture.
  Tracking record fields still inactive zeros. ARM callback continuationKI-0699.
- c393/a663 verified3270syscall/116dispatch/1523IPC/33dialog-audit tests,
  180 isolated hosted crates, both builds/features and no stack increase.
  Logs /tmp/B3630-scroll-procedure-*.log. Release x86 saved
  target/B3630-release-stack-x86.elf SHA82be120b948019627f641cfe9f8bf3c0c1e441f82d7d02f0f67fd556ea45e8ed.
- KI-0890 default mouse-activation parent/caption semantics; KI-0462 cursor
  parent-first policy; KI-0604 full actual input/menu boundary coverage open.
- KI-0891 old detached VM exit provenance missing, preserve earlier logs.
- Full Notepad issuesKI-0859/0860/0861/0862/0863/0865 remain open.
- Durable evidence scratch/B3630-notepad-verification.md. Keep PR draft.

## Companion repos / publishing

- packages B3630-wine-profiles6830f27 clean, no remote.
- images B3630-wine-profiles553217b, no remote; preserve .dist-old-layout/.
- Wine named source/build/artifact/catalog/RPM paths and stamps documented39§13;
  OXIDE_WINE_PROFILE=release|debug independent of kernel PROFILE.
- PR7680 body /tmp/B3630-pr-body.md records current fixes and validation.
  Push0c9a8101c passed180 isolated hosted crates and both feature checks.
  Only documented KI-0019 lint/test-build/stack exceptions used after baseline
  proof. No new/increased stack path, no hosted/feature bypass.
- Push policy only known KI-0019 exceptions after actual baseline proof:
  SKIP_LINT_RATCHET, SKIP_TEST_BUILD_GATE, SKIP_STACK_GATE. Never skip hosted
  or feature checks; no new/increased stack path. Verify remote SHA after push.
