# B3630 scrollbar control enable state

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0903 |

EnableScrollBar selects existing optional control-owned state for SB_CTL.
Both-arrow requests change canonical enabled state; visibility is preserved.
Partial-arrow requests leave enabled state unchanged. Control requests return
TRUE even when flags are unchanged; standard bars keep their separate flags.
ShowScrollBar continues to change control visibility explicitly.

Actual bar_live::route boundary initially returned0 before state mutation
(/tmp/B3630-scroll-enable-red.log). After state wiring, restoring ShowWindow
instead of EnableWindow fails the visible-control regression, exit101
(/tmp/B3630-scroll-enable-show-control-red.log). Corrected boundary passes21
tests, exit0 (/tmp/B3630-scroll-enable-green.log); IPC library1529 pass.
Fixture now uses canonical show, matching production ShowWindow, rather than
set_visible, which does not synchronize WS_VISIBLE. Canonical enable_window
consumes style bits and correctly exposes that inconsistent fixture state.

Hosted task/usercopy/publication seams remain explicit. Raster invocation is
observed, not rendered pixels. Control refresh still requires callback/DC
ownership under KI0885. Existing EnableWindow state helper lacks synchronous
WM_CANCELMODE/WM_ENABLE and accessibility notification (KI0904); this change
does not claim those semantics or full visual acceptance.

Both builds and features pass; both frame gates pass. Static gates retain
existing KI0019 failures. ARM278 primary rows unchanged; x86 retains336 rows
but one router path grows16 bytes (14792->14808). Disassembly parser measures
its own frame272->288; deepest successor remains dispatch_mode through the
ShowWindow branch. Enable-state temporaries were inlined into that shared
router frame. Isolating enable as a non-inlined operation is under validation;
no increased-path exception or successful final stack claim.
/tmp/B3630-scroll-enable-{final-build,feature,frame-x86,frame-arm,stack-x86,stack-arm}.log;
/tmp/B3630-scroll-enable-stack-paths-x86.log. No new boot.
