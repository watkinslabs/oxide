# B3630 default mouse activation

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0890 |
| CLAIMED | B3630-paint-region-collapse | KI0462 cursor follow-up |

Default mouse activation now forwards child requests to the canonical parent
through the existing resumable Send owner, outside GUI ownership. Original
wParam/lParam retained. Canonical relative_parent gives popup ownership
precedence when both child/popup style bits are present; dedicated regression
fails with direct tree-parent lookup (/tmp/B3630-mouse-owner-red.log). Nonzero parent LRESULT wins, including activate/eat,
no-activate/eat and all64 result bits. Zero or failed send selects the child
fallback: caption plus left-button-down returns MA_NOACTIVATE, other clicks
MA_ACTIVATE. Pointer policy lives in IPC; syscalls snapshot ownership and
adapt sent-message completion. Each existing continuation stores its fallback
value directly; no extra queue or callback registry.

Actual production DefaultWindowProc dispatcher tests: parent arguments,
non-child non-forwarding, caption/client/button classification, zero/failure,
suspended completion and no duplicate send. Parent callback execution is a
named hosted seam; existing send tests own transport coverage. No claim of
real User32/ARM callback or rendered-desktop acceptance from this fixture.

Before repair: caption assertion fails (0 vs3). Independent parent-only run
fails (0 vs1), exit101. Full pre-fix suite also contains mutex-poison cascades;
those are not independent causal reproductions.
/tmp/B3630-mouse-activation-red.log; /tmp/B3630-mouse-parent-red.log.
After repair:128 production-dispatch fixture tests pass, exit0.
/tmp/B3630-mouse-activation-green.log. IPC1529 library tests pass.

Raw NtUserMessageCall default-procedure selector already routes mouse
activation to the native DefaultWindowProc dispatcher; repaired live handler
is reached by that existing call. Parent callbacks use send_resumable_current
and preserve the distinction between immediate completion and pending work.

No new boot; full Notepad runtime acceptance and GNOME startup cause remain
open. Prior verification never displayed GNOME; user closed that VM.

Final validation: make build and make feature-gate exit0 for both architectures;
both frame gates exit0. Static stack gates exit1 on existing KI0019 failures,
with336x86/278ARM primary rows unchanged and no added/increased path versus
futex-site baseline; exception7664/6368 unchanged. Full stack gate not green.
/tmp/B3630-parent-handling-final-{build,feature}.log;
/tmp/B3630-parent-handling-{frame,stack}-{x86,arm}.log;
/tmp/B3630-parent-handling-stack-compare.log. Current snapshots:
x86_64: 3c6f28cfd0d10e49d7f22a29e9f7cb5050e34f5e173dd8efc538d07e4a81e512 target/B3630-parent-handling-x86_64.elf
aarch64: da6783bb6bb2f7edf6fb4443401bc41404ac4ea8add84496fd4a794feb6e4a63 target/B3630-parent-handling-aarch64.elf
