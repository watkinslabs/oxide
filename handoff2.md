# Handoff — Notepad acceptance and desktop startup

First command: `git -C /home/nd/oxide/kernel-B3630 status --short`

Branch B3630-paint-region-collapse; draft PR #7680. Main unchanged.
User goal: working Notepad borders, buttons, menus, About, Save/Open dialogs.
User explicitly requested harness dialog coverage. Goal remains active.

## Implemented and checked

- `tools/notepad_dialogs.py` wired into acceptance `run_desktop_checks`:
  all five menus must open/dismiss with visible entries, rejecting baseline text;
  About + OK/license, Save As + Save/Cancel, expanded file-type filters,
  named Save, New, Open, content round trip, both Cancel buttons.
- 25 Python tests pass; removal of dialog hook and title-only evidence
  produce red tests. First-line fixture exposed fixed65px crop bug; crop
  now starts below measured File menu text.
- `af36316b1`: X11 empty extents use 1x1 backing without feeding padded
  geometry into logical state; obsolete ConfigureNotify rejected by sequence.
  Two real Xvfb tests red before respective fixes; 90 compositor tests pass.
- x86 compositor builds; ARM release builds using local Fedora sysroot
  `target/B3630-arm-sysroot` completed from cached RPMs. Default sysroot
  defects KI-0421/KI-0691 remain open.
- Hosted gate 180 crates pass; both kernel feature gates pass.
- KI-0019: pre-existing lint-ratchet/test-build/stack failures; only their
  named SKIP flags used for push. See scratch/B3630-notepad-verification.md.

## Runtime blocked before Notepad

One acceptance boot: runner76178, QEMU79681, artifacts under
`target/B3630-acceptance`, build id B3630-dialogs. Check process liveness
before assuming either remains. Log `/tmp/B3630-acceptance-run.log`.
GNOME reports running at21.114s; screenshot stays console ending13.670s.
No Notepad or bridge launch: this cannot validate our dialog/geometry changes.
KI-0865: active sessionVT2, GNOME394 has card0 open; session DBus works,
DisplayConfig query times out, main thread private-futex-waits indefinitely.
Thread snapshot `/tmp/B3630-guest-threads.txt`. Cause unconfirmed.
KI-0866: GDB failed to obtain backtrace; owned tracer1111 killed and GNOME
resumed (State S, TracerPid0). Debugger briefly stopped it: account for this
when interpreting the final acceptance timeout.
Local SSH forwarding127.0.0.1:22363 was added to this VM via QMP only.
Do not launch another diagnostic boot; retain this boot's evidence.

## Corrected earlier hypotheses

KI-0861: saved UART ShowWindow result-rect prints CLIENT geometry, already
750x1 before paint clipping. Earlier claim damage alone collapsed is unsupported.
KI-0859 captions unresolved. Prior instrumented boot did not open About;
absence of extent traces cannot clear all measurement paths or metrics.
Window geometry coordinate conversions examined but no defect proved there.
Do not treat the X11 fixes as proof these Notepad symptoms are resolved.

Open: real dialog result, all menu dispatch, border/move/resize/occlusion,
both-architecture runtime verification. Evidence/plan:
`scratch/B3630-notepad-verification.md`. Do not merge or mark goal complete.

Final acceptance result: exit 1, "GNOME session marker appeared without a
rendered desktop frame". Runner76178 and QEMU79681 both exited; no live VM
remains. UART audit passes with no Windows calls, since Notepad never launched.
