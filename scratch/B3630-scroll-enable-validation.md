# B3630 scrollbar control enable state

| Status | Branch | Item |
|---|---|---|
| FIXED 13f9a59e9 | B3630-paint-region-collapse | KI0903 |

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

Final source37f740be7: both builds/features and frame gates pass. Existing
KI0019 static failures remain336x86/278ARM primary rows; no added/increased
path versus parent-handling. Accessibility query storage is kept off the
shared router frame; its deepest x86 path falls14792->14744. Enable-only
separation did not help and was removed; disassembly identified query buffers
in the shared frame. No stack exception added. Validation and final ELF hashes
are shared with scratch/B3630-sizegrip-validation.md. No new boot yet.
