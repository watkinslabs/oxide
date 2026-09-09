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
  No runtime claim yet. Both release builds launched; check own job/log.
- KI-0882: harness selects actual File→Open before broad menu checks, waits
  for Open/Cancel controls, and retains failed live VM/sockets by default.
  OXIDE_NOTEPAD_KEEP_ON_FAILURE=0 opts into termination. Pointer clicks release
  before capture and park outside captions. Shutdown timeout fails.
- KI-0884: audit detects create/bridge refusals. Actual Open log now FAILs
  with4 findings.43 relevant harness/audit tests pass;5 restored-defect
  controls fail. Source changes need commit/publication verification.
- Claims committed1a7214aa5 and6124d97; prior claimKI0882 b5fcd305f.
- Last verified remote b7398c33f; re-fetch before assuming publication.
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
