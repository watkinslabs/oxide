# Handoff — Wine profiles and user-visible Notepad

First command: `git -C /home/nd/oxide/kernel-B3630 status --short`

Branch B3630-paint-region-collapse; draft PR #7680. Main read-only.
Goal remains all Notepad borders/redrawing/buttons/Save/Open/dropdowns/About
working and verified. Read CLAUDE.md. Consult pinned local sources first.
Durable evidence: scratch/B3630-notepad-verification.md.

## Live user session

- User requested a visible launch. QEMU PID708994 was started with GTK/KVM;
  revalidate PID and argv before acting. Do not stop it or overwrite its disks.
- Namespace target/builds/notepad-debug-696997; current kernel was rebuilt.
- QMP target/B3630-user-debug/qmp.sock; UART target/B3630-user-debug/uart.sock.
- Serial target/boot-logs/x86_64-20260909-140413.log; launcher log
  target/B3630-user-debug/qemu.log. QEMU writes serial independently of reader.
- Initial frame showed console; later frame shows GNOME and Notepad with
  user-entered text. User controls input; do not run automated UI checks over it.
- Button diagnostics show OK caption, nonzero measurement and draw success.
  Save/Open/About/dropdown/redraw correctness still needs complete evidence.

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
