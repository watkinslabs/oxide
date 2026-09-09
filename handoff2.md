# Handoff — Notepad callbacks implemented; runtime still unverified

First command: `git -C /home/nd/oxide/kernel-B3630 status --short`
Branch B3630-paint-region-collapse; draft PR #7680. Verify local/remote SHAs
before assuming the last push finished. Main remains read-only. Goal active:
Notepad borders, buttons, menus, About, Save/Open and dropdowns must work.

## Implemented

- Harness: all five menus open/dismiss; About, Save As, Open, visible captions,
  file-type dropdowns, OK/Save/Open/Cancel, saved-content round trip below menu.
  25 Python tests pass with positive controls for wiring and false evidence.
- X11 empty backing and stale configure notification fixes:90 compositor tests,
  including real Xvfb regressions. x86 and ARM compositor builds pass; ARM used
  task-local completed Fedora sysroot (default gaps KI-0421/KI-0691 remain).
- Atomic rejected resize03758d7e3:529 window-manager tests pass.
- KI-0641 b6447279e + nested fix1787af1ac: procedure-bearing Configure packets
  enter remote_positions; owner thread runs CHANGING/NCCALCSIZE/CHANGED before
  canonical geometry commits. Callback-free windows keep direct delivery.
  Origin Local/Remote/Compositor controls retrieval and geometry publication;
  nested same-HWND positions mark pending compositor work for correction.
- Queued move/size flags computed at consumption, preserving rapid returns to
  original size. Display geometry does not echo unless application corrects it.
- KI-0868 fixed232e63fd5: prepare_current completes raw-argument planning before
  callback execution. Measured Windows routes19136/18816 B, baseline19168/18848.
  Over-budget paths338 ->336; every remaining entry is unchanged or smaller.
  No allowance changed. Archived baseline/fixed stack logs named KI0868.
- 3255 syscall lib tests and30 callback-boundary tests pass, with positive
  controls for packet wiring, callback execution, queue ordering, application
  corrections, nested updates and failed/no-op preparation outcomes.

Only pre-existing KI-0019 gate failures may be bypassed. Callback publication
was held while stack use regressed; that regression is now removed. Keep PR
DRAFT until runtime requirements are verified. Plan/evidence:
`scratch/B3630-notepad-verification.md`.

## Runtime evidence and next work

One acceptance run76178 failed: "GNOME session marker appeared without a
rendered desktop frame". QEMU79681 exited; no owned guest remains. Artifacts
`target/B3630-acceptance`, buildB3630-dialogs. GNOME reports running21.114s,
framebuffer remains console ending13.670s. Notepad never launched (KI-0865).
SessionVT2 active, DRM open; session DBus responds, DisplayConfig times out;
GNOME main thread waits on a private futex. Cause unconfirmed. GDB failed to
produce a backtrace (KI-0866); tracer killed and GNOME resumed before timeout.
No callback fix has runtime verification. Do not use another boot to debug.

KI-0861 saved UART: custom dialog600x30 at72.517 becomes750x1 after parent and
child resize callbacks. Source layout resizes child to parent client size;
requested parent rect and returned NCCALCSIZE rect are absent from that log.
KI-0859 captions unproven; old measurement-cleared claim unsupported.
Open: desktop startup, actual dialog/border/menu behavior and both architecture
runtime results. Do not merge or mark goal complete on hosted test evidence.
