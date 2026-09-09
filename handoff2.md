# Handoff — Wine profiles and user-visible Notepad

First command: `git -C /home/nd/oxide/kernel-B3630 status --short`

Branch B3630-paint-region-collapse; draft PR #7680. Main read-only.
Goal remains all Notepad borders/redrawing/buttons/Save/Open/dropdowns/About
working and verified. Read CLAUDE.md. Consult pinned local sources first.
Durable evidence: scratch/B3630-notepad-verification.md.

## Runtime evidence and next verification

- Both VMs have exited. Revalidate ps before any later launch; no boot loops.
- User-visible run namespace notepad-debug-696997 reached GNOME and Notepad
  with user text. Serial target/boot-logs/x86_64-20260909-140413.log.
- Final automated run759158 used separate namespace B3630-debug-final;
  target/B3630-debug-final contains UART, screenshots, cadence and audit files.
  /tmp/B3630-debug-final-acceptance.log records terminal exit1.
- This automated run reached Notepad but failed BEFORE dialogs: expected token
  oxide-b3630-final absent, displayed suffix -0-final; crop wrongly ended y165.
- KI-0880: frame_extent followed inset columns into dark edit border. Repair
  follows outer frame edges; retained real PNG measures(148,122,877,692), and
  still correctly rejects missing full token. Synthetic border control too.
- KI-0881: asynchronous send-key chord releases raced immediate text events.
  Verified input scheduling in pinned QEMU9.2.4 source. All correctness chords
  now use immediate ordered press/release events. Removed timed comparative
  typing experiment from correctness run; actual token cadence still reported.
- Restoring either defect fails its hosted regression. No subsequent boot;
  commit/publication and ledger status for these repairs need checking.
- Goal still requires visible Save/Open/About/dropdowns and redraw correctness.

## Current profile work

- OXIDE_WINE_PROFILE=release|debug, default release; kernel PROFILE independent.
- Source/build/dest directories and artifact catalogs have explicit suffixes.
- RPMs oxide-wine-release and oxide-wine-debug install physical windows-<profile>
  catalogs. Image selection sets common loader aliases to the selected catalog.
- Version/profile/preparation-input ID stamps; mismatch gates in packaging,
  image compose, payload staging, cached xtask launch and wrapper.
- Both full builds and named RPMs completed. Debug image composed through flag;
  actual installed RPM and extracted user32 hash match named debug artifacts.
- Source profile gate and full staged payload gate pass. Wrong-profile commands
  fail before build/boot.95 xtask tests/19 payload/28 harness/5 cache/17 package/
  2 image tests pass; existing xtask ignored test remains. Hook controls fail red.
- packages commit6830f27d0530148550646cfa95c582ea67826383 and images commit
  553217b1bd369f34a9e41e24ad81870ec967e0ad on B3630-wine-profiles; neither repo
  has a remote. Preserve images/.dist-old-layout (pre-existing untracked).
- Kernel profiles implemented in d4043445d; KI-0878 archived fixed with that SHA.
  Publication status and draft PR update still need verification.

## UART audit follow-up

- KI-0879: replaced host Wine name decoding with a preboot map extracted from
  the selected staged image;19 audit tests and29 harness tests pass. Check
  commit/publication status. Live log audit clean; UI correctness still open.
- Earlier availability question referred to the now-exited manual VM.

## Earlier repairs and remaining evidence

- Published remote last verifiedab8fa3bb9878bdf45e5e53a9c7542751f1b0bee7;
  re-fetch before assuming publication. Local geometry changesab216dba9 and
  stack repair174ef9636 plus claims were unpublished at profile task start.
- Geometry trace captures request/after-changing/raw NCCALC input+answer/commit.
  Final stack reports exactly match prior baseline both arches; KI-0877 fixed
  in ledger using174ef9636. No new/worsened stack path.
- Harness covers five menus, About, Open/Save, file-type dropdowns, buttons and
  file-content round trip. Prior automated run failed before Notepad when GNOME
  did not render. Current manual launch reached desktop; do not conflate them.
- Prior GDB ABI repairs: selectors e7dde8192, vDSO05071e0f1, private attach stop
  0fe94a760, traced worker stop/exit identity and retentiondc3fbe15e.
  GNOME stall cause was not established; current run alone does not establish it.
- X11 empty/stale Configure, atomic resize and owner-thread resize callbacks
  already repaired; detailed tests/SHAs in scratch plan and git history.
- KI-0859 caption hypothesis unproven; fresh button trace supplies missing
  actual caption lookup/measurement/draw outcomes. Dialog750x1 origin KI-0861
  needs analysis against new geometry boundaries if reproduced.
- Keep PR draft until requirements verified. Only known KI-0019 gate bypasses
  permitted after baseline proof; no new stack regression or hook bypass.
