# Handoff — actual Notepad Open failure

First command: `git -C /home/nd/oxide/kernel-B3630 status --short`

Branch B3630-paint-region-collapse; draft PR #7680; main read-only.
Read CLAUDE.md; consult pinned local sources first. Goal: all Notepad
borders/redrawing/buttons/Save/Open/dropdowns/About working and verified.
Durable evidence: scratch/B3630-notepad-verification.md.

## Latest runtime

- User rejected automated menu-only verification that killed QEMU before an
  item was selected. Run804065 did paint the full token after input/frame
  repairs92373c14a, then failed File-menu OCR before dialogs.
- Actual visible follow-up clicked File then Open; black horizontal strip,
  no usable Open dialog. target/B3630-dialog-live/{file-menu-painted,
  open-dialog-stable}.png and commands.jsonl preserve action/evidence.
- Serial target/boot-logs/x86_64-20260909-143112.log records toolbar creation
  failure plus three compositor bridge refusals; caption draw succeeds.
  Parent100005 and child10001c are750x484, not previous750x1 observation.
  Sizegrip10001b repeats WM_PAINT returningc0000002.
- QEMU808134 later absent; log ends at169.713s mid-line. Cause unknown.
  No live QEMU as of14:45UTC; revalidate. Never kill a user's inspection VM.

## Current repairs

- KI-0883: canonical GW_CHILD/FIRST/LAST endpoints inverted relative to
  NEXT and hwnd_list. Child→list→control-id lookup regression fails old code;
  repaired ordering passes1512 IPC lib tests and both feature-gate targets.
  No runtime claim yet. Both release builds passed. Stack reports match
  preceding reports exactly (358/299 rows including existing failures).
- KI-0882: harness selects actual File→Open before broad menu checks, waits
  for Open/Cancel controls, and retains failed live VM/sockets by default.
  OXIDE_NOTEPAD_KEEP_ON_FAILURE=0 opts into termination. Pointer clicks release
  before capture and park outside captions. Shutdown timeout fails.
- KI-0884: audit detects create/bridge refusals. Actual Open log now FAILs
  with4 findings.43 relevant harness/audit tests pass;5 restored-defect
  controls fail. Implemented322669c2a; ledger archived with that SHA.
- Claims committed1a7214aa5 and6124d97; prior claimKI0882 b5fcd305f.
- Last verified remote940591edd; hosted180 and both feature gates pass.
- KI-0885 claimed940591edd; still unimplemented: scrollbar procedure selector029a has no dispatch arm,
  returns STATUS_NOT_IMPLEMENTED for WM_CREATE/WM_PAINT. Actual debug DLL
  disassembly identifies the repeated callback as ScrollBarWndProc_W.
- Current LIVE QEMU832847 (launcher832789), named debug namespace
  B3630-debug-dialogs. Do not kill. QMP target/B3630-debug-dialogs/qmp-831735.sock,
  UART uart-831735.sock; serial x86_64-20260909-145749.log.
  Acceptance831735 failed Open-item visibility while About was on screen;
  automatic input stopped and VM/sockets retained as designed.
- User reports corrupted rendering and controls not receiving clicks.
  user-wacky.png / before-dispatch-click.png capture trails/blank captions.
  KI0887 records this; Position op7 refused at56.526, caption draw succeeds.
- KI0886 claimed: controlled click655,463 reaches button100007 WM_NCHITTEST,
  returns0 and is discarded (only WM_SETCURSOR afterward). DefaultProc uses
  parent-relative state.rect against screen lParam. Reuse rect_query Window
  mapping at default-procedure boundary; source confirms screen rect test.
  Repair now wired through default_proc_state to canonical screen query.
 3262 syscall lib/116 actual-dispatch fixture tests pass; old hook fails0vs1.
 Both release/feature targets pass; no increased/new stack row. Not live yet.
- KI0887: CS_PARENTDC paints parent backing, but default X11 child clipping
 hid those pixels. IncludeInferiors repair passes real Xvfb RED/GREEN test
 and full97-test compositor suite; both release targets build. Not live yet.
 Pointer trails/stale menu cause remains unverified; row stays IN-PROGRESS.
  PR must remain draft: complete visual acceptance not achieved.

## Wine profiles

- Wine11.16; OXIDE_WINE_PROFILE=release|debug (default release), independent
  of kernel PROFILE. Named source/build/artifact/catalog paths and RPMs;
  stamps/profile gates cover composition, cache, staging and launch.
- Both full builds and named RPMs complete. Source GNOME image selects debug;
  packaged/extracted user32 hash matches debug artifact. No host-Wine fallback.
- packages6830f27 and images553217b on B3630-wine-profiles, no configured
  remotes. Preserve images/.dist-old-layout pre-existing untracked directory.
- Kernel profile commitd4043445d, UART guest ordinal capture38abeac2c.
  Previous tests:95 xtask(1 ignored),19 payload,5 cache,17 package,2 image.

## Existing repairs and constraints

- Resize callbacks, stale/zero X11 Configure, atomic rejected resizes already
  repaired. Geometry/caption traces retained; button traces debug-only.
- Geometry stack repair174ef9636 equals previous baseline on both arches:
  336/277 existing over-budget paths,7664/6368-byte exception reservations.
- Only documented KI-0019 bypasses: SKIP_LINT_RATCHET,
  SKIP_TEST_BUILD_GATE, SKIP_STACK_GATE after baseline proof. No new increase.
- Earlier selectors/vDSO/ptrace fixes remain; earlier GNOME stall cause unknown.
- Open remainingKI0859/0860/0861/0862/0863; do not close on kernel test counts.

## Immediate implementation work

-0190b0530 commits parent-DC presentation repair;940591edd claimsKI0885.
 PR body updated for click repair and retained VM. Screenshot
 target/B3630-debug-dialogs/dispatcher-current.png still shows corrupted About.
-721f8120d: KI0885 control-state foundation adds optional storage to OwnedWindow;
 scroll/control owns initialization, info/range/flags with3 targeted tests.
 Removing initialization fails all3; full IPC suite1515 passes restored.
 No production raw scrollbar-procedure arm yet; do not claim it implemented.
- KI0888 claimed: shared ScrollState::apply_for_bar does not maintain flags,
 skips page-only hiding and mishandles DISABLENOSCROLL-only. Correct this
 canonical policy before consuming it; new control helper currently reuses it.
- Remaining scrollbar work: all selector029a messages, canonical state and
 tracking, paint Begin/Draw callback/End lifecycle, focus/caret, sizegrip
 resize commands and cursor, scroll info/accessibility; actual dispatch tests.
- Pinned source draw uses user callback with a draw parameter record; existing
 nt_rtl::begin_user_callback only accepts a user pointer, no record-copy helper.
 Paint preparation already retains Prepared in paint_callbacks::Completion;
 extend that lifecycle for control painting so callbacks cannot lose HDCs.
 Read source again before implementation; no WM_PAINT-only success stub.
- Both release kernels build after721f8120d; stack reports exactly match
 the preceding dispatcher repair on both arches. No new/increased row.
