# Queue repair desktop verification

| Status | Branch | Work |
|---|---|---|
| FAILED | B3630-paint-region-collapse | KI0887 visible redraw/input acceptance |

Runtime b94456156; validation31bfbe029. Fresh Wine11.16 debug profile stamp
000982e8e976863f0a29925ab7426d09808a3e61c125c18decc4cf77f27af5da.
Image target/builds/B3630-queue-verification-debug/oxide-x86_64-grub.iso SHA256
8e02a11dc0abf3cfc5919be0115e06c6a46f45ef0bb55ccfb66fd85a57d23631.
Run /tmp/B3630-queue-verification.py run; GNOME started and Notepad launched.
Initial document check failed; automatic dialog/menu checks never ran.
Screen target/B3630-queue-verification-debug/screen-3595455-initial-token.ppm
shows overlapping Notepad images, cursor trails, typed token in rear image,
blank foreground edit area. PNG inspection copy /tmp/B3630-current-screen.png.
This is not a successful Notepad acceptance result.

Output target/B3630-queue-verification-debug; live.json launcher3595458,
UART uart-3595455.log; serial target/boot-logs/x86_64-20260910-110048.log.
Later UART contains dialog activity after automated check failure; origin of
that interaction not established here. Readback matched counters1..61,
six unavailable markers, one mismatch at210.189s HWND10000f:430x276,
16340 mismatches, first(0,0,13947080,0). Matching edit frames does not prove
full desktop composition. Later mismatch also needs occlusion analysis.
Audit audit-3619138.md FAIL: mismatch plus two text-measure refusals DC0.
Restack BadMatch messages already have synthetic ConfigureRequest handling
in x11/position.rs; raw rejection is not proof that reconfiguration failed.
Do not implement another restack fallback without inspecting existing path.

Helper retained VM after failure and waited for launcher. Launcher later
exited0 at1789038270.3824806; no shutdown/quit sent by helper. Cause unknown.
No QEMU remains. QMP localhost2222 forwarding added for read-only guest
inspection; probe with boot-smoke credentials rejected, corrected image
credentials attempted after VM exit and connection refused. No guest commands
executed through SSH. Guest image build.sh defines image account separately.

Current narrowed investigation: correlate complete compositor output with
scanout pixels and window placement. Atomic KMS currently presents a full
surface through kms_ext::atomic_primary, so missing partial-damage widening
is not established as the cause. No new graphics runtime repair made here.

Further trace review: PE starts59.015s and65.819s, separate loader/module
initialization and main-window creation HWND100001 at59.718s versus200001
at66.358s. The screenshot contains two application windows; classifying all
overlap as stale scanout pixels was premature. Cause of the second startup
is not established. Existing startup trace now adds current task ID and image
path (KI0918), preserving entry-prefix compatibility. No additional registry.
One visible-launch wrapper command is present in UART; shared per-prefix
windows-launch.log is truncated on another wrapper invocation, so its absence
cannot rule out another wrapper. Distinguish separate task launch from same-
task re-exec before deciding which layer owns the blank foreground instance.

KI0918 trace129a1d5a9: current task ID and image path appended to existing
PE-start marker. Both target compile checks PASS after correcting str/bytes;
release/frame/static and live identity capture pending.
KI0919 wrapper log selection now includes Wine profile and launcher PID;
header reports launcher/profile/log path. Executing the actual log-init shell
fragment for two launches reproduces the old shared-file clobber (RED).
No launch serialization or singleton restriction introduced.

All four Notepad staging/wrapper tests PASS after per-launch path repair;
logs /tmp/B3630-launch-logs-{red,green}.log. New image must actually inject
updated wrapper; reusing an already-staged root would retain old log path.

Identity trace release validation: both builds/features/frame gates PASS;
static KI0019 baseline remains exit1,335x86/278ARM primary rows unchanged
with no added/increased paths versus peek-classes. Final ELF SHA256:
- x86_64:f3ef4be41e6e007ac4b010586954a069632b71ec108d80c2283b8f373fbc262d
- aarch64:3b98275484c87713e791a17b5608aedc6bf9887c136f627635faa5676c65b104
Logs /tmp/B3630-pe-identity-{build-x86,build-arm,feature,frame-x86,frame-arm,
stack-x86,stack-arm}.log. KI0918 actual startup identity capture pending.
Next helper /tmp/B3630-identity-verification.py prepare|run uses fresh identity
image/output ID and new wrapper. Prepared process capture via local SSH;
records PE identities before input and refuses ambiguous multiple starts.
This is an acceptance precondition, not a ban on multiple application instances.
Image preparation79876 running; no live QEMU. Last branch push54d8d6e74
verified remote; newer instrumentation/log commits not yet published.


Identity live run3672188 (ISO eaa78fc48417325c34b0dc767a7031f5c6349672ec7beeda1ee161a39012d6a4):
- GTK/KVM/GNOME, one PE startup50.694s, canonical tid13c7 and image
  C:\windows\system32\notepad.exe. Guest PID951, wrapper932, compositor1000;
  task IDs and guest namespace PIDs are different identifiers. KI0918 verified.
- Installed wrapper reports windows-launch-debug-932.log; KI0919 live confirmed.
- Initial document token oxide-b3630-identity visible. First automated File
  click failed: HTMENU5, WM_NCLBUTTONDOWN delivered, popup HWND100004 created,
  WM_UNINITMENUPOPUP and WM_EXITMENULOOP followed before popup paint.
- Holding press before release opens File; stays open after release. Screens
  /tmp/B3630-menu-{press2,release2}.png. No claim of full redraw correctness.
- KI0920 cause: evdev capture /tmp/B3630-pointer-capture.log records press,
  release, then pointer movement. X RECORD /tmp/B3630-record-capture.log sees
  press at168,156, then movement1004,748 with button held, then release there.
  Immediate post-click parking dismisses the menu under desktop event delivery.
  Preserve pointer position while verifying click result; no timeout increase.
- Read-only X observer could not see events during grabs; X RECORD supplied
  device events. strace attach failed PTRACE_LISTEN with EIO (existing KI0872);
  detached; compositor state S afterwards. No tracee/VM killed.
- VM retained, live.json in target/B3630-identity-verification-debug; QEMU3672245,
  original runner session82991. SSH bound localhost2222 only. Menu/dialog
  acceptance remains open; no automatic dialog steps passed yet.
