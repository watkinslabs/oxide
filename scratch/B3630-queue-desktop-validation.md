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
