# Handoff — hardware retrieval repair, verification in progress

First command: `tail -15 /tmp/B3630-hardware-dispatch-build.log`
Worktree /home/nd/oxide/kernel-B3630; branch B3630-paint-region-collapse.
Main read-only. Read CLAUDE.md. Draft PR7680; last verified remote843f82ed4.
Local HEADc9834ba26; current hardware commits NOT pushed (stack regression).
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

-11 hardware-driver tests and119 production-dispatch fixture tests pass.
-1526 IPC and3270 syscall library tests pass after API cleanup and target
  lifetime check; /tmp/B3630-hardware-final-{ipc,syscalls}.log.
- Positive controls raw overwrite, transparent-walk bypass, and ignored
  Stage::Prepared dispatch hook each fail assertions, restored afterward.
  Logs /tmp/B3630-hardware-{raw-view,transparent,view-hook}-red.log.
- /tmp/B3630-hardware-boundary-final.log current tests.
- Both feature checks passed initial implementation; final tracing/checks
  require repeat. /tmp/B3630-hardware-feature.log is INITIAL pass only.
- Initial build53277 passed both; follow-up47613/73320 passed both builds and
  features after target-lifetime fix. Then stack regression found on x86.
- x86 stack358 rows but dispatch15088→15232; initial hardware live drive
  13952→13968. Do NOT call this baseline-only or bypass it.
-249d43553 extracts delivery/usercopy and shared Get tracing from dispatcher.
  Tests pass; x86 stack improves to15168 but still80 above old dispatch path.
  Usercopy fixture now asserts GUI unlocked and rejects unexpected copies.
- c9834ba26 adds small DispatchStage and noninlined dispatch_for_current helper
  so general dispatcher no longer carries full message result payload.
  11 driver/119 dispatcher tests pass in /tmp/B3630-hardware-dispatch-tests.log.
- Current build85677: /tmp/B3630-hardware-dispatch-build.log, both arches.
  Prior build45257 and feature10998 may still finish; poll authoritative exits.
  Their logs /tmp/B3630-hardware-delivery-{build,feature}.log.
- After85677, rerun both stack reports with label hardware-dispatch. Do not
  push until no new/increased numeric rows (normalize annotation changes when
  interpreting identities but preserve full reports). No boot launched.
- Previous baseline358x86/299ARM report rows,
  336/277 existing overbudget paths,7664/6368 exception bytes (KI-0019).
  Compare /tmp/B3630-scroll-procedure-stack-{x86,arm}.log against final ELF
  reports, no new/increased path allowed. ARM has NO stack-switch-map option.
- Worktree refreshed by fetch origin main + ff-only merge (already up to date),
  then reconciliation timestamp refreshed; worktree guard passed.
- No stash, formatters, main edits or new bypasses. Explicit stage paths.

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
- PR7680 body /tmp/B3630-pr-body.md now describes local follow-ups explicitly
  as unpushed, pending stack repair. Update after actual push/remote SHA check.
- Push policy only known KI-0019 exceptions after actual baseline proof:
  SKIP_LINT_RATCHET, SKIP_TEST_BUILD_GATE, SKIP_STACK_GATE. Never skip hosted
  or feature checks; no new/increased stack path. Verify remote SHA after push.
