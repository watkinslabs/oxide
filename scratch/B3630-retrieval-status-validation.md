# Retrieval arrival acknowledgement

| Status | Branch | Work |
|---|---|---|
| IMPLEMENTED | B3630-paint-region-collapse | KI0913 dispatcher and stored-bit acknowledgement |
| OPEN | B3630-paint-region-collapse | KI0915 paint status observation; KI0914 Peek flag semantics |

The actual Get/Peek dispatcher invokes retrieval_status after sent callbacks
and before hardware/posted scanning. Invalid HWND filters leave changed bits
intact. WindowManager owns the mutation: upper-word classes default to
QS_ALLINPUT; posted selection clears posted/hotkey/timer changes; all-posted
clears only for a full numeric range, independent of HWND restriction; any
input selection acknowledges all input classes; paint selection clears its
stored changed bit. Wake bits and pending messages remain unchanged.

Four owner/policy tests and five actual dispatcher tests cover low-flag
independence, numeric range normalization, per-thread and selected classes,
unsuccessful scan, nonremoving Peek, invalid HWND and pending sent callback
ordering. Full IPC1548 and syscall3276 library tests PASS; dispatcher144,
message-wait/status35, send70 PASS. Task/callback/usercopy/hardware-stage seams
are hosted; no guest DLL executes. Posted copy seam checks the delivered
message; it does not claim usercopy lock safety or hardware processing.

Five controls each execute one failing dispatcher test: remove wiring, move
acknowledgement before sent callbacks, clear all-posted for restricted ranges,
ignore selected classes, or clear before HWND validation. Restore and full
suites PASS. Logs /tmp/B3630-retrieval-status-{owner,ipc,dispatch,tests,
control-wiring,control-ordering,control-range,control-classes,
control-invalid-filter}.log. Initial790058093 release/features PASS; x86
frame gate PASS but dispatcher frame1424->1440 added16 bytes on11 deep paths.
Replaced borrowed NtWindowCall argument with scalar HWND/range/flags. All144
dispatcher tests PASS; final release/static validation still required.
Logs /tmp/B3630-retrieval-status-{build-x86_64,build-aarch64,feature,
frame-x86,stack-x86,path-x86,scalar-tests}.log.

KI0913 remains in progress pending full paint-status observation: queue_status
synthesizes QS_PAINT as changed while dirty (KI0915). Peek still treats any
nonzero flags as removal and ignores queue-class selection (KI0914). Wait
flags KI0712, object acquisition/deadlines KI0912 and handle stride KI0844
remain open. No VM; full Notepad dialog/input/redraw acceptance outstanding.
