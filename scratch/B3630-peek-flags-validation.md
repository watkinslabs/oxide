# Peek retrieval flags

| Status | Branch | Work |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0914 removal bit and queue class selection |

Only PM_REMOVE consumes a retrieved message. PM_NOYIELD and upper-word
class flags independently preserve a nonremoving retrieval. Correct all
three actual dispatcher/hardware decisions, with boundary regression.
Class filtering must use existing canonical queue origins and paint state;
no copied queue or status registry. Full class selection still outstanding.

Removal decisions now use canonical PM_REMOVE in dispatch.rs,
hardware/live.rs and hardware/delivery.rs. Actual posted retrieval regression
fails before repair (wake264 becomes0); hardware delivery control restores
old boolean and fails (selected raw entry disappears). Restored complete
production dispatcher fixture:147 PASS. Hardware fixture supplies prepared
view; it proves delivery, not the live hit-test ladder. Logs:
/tmp/B3630-peek-flags-{red,hardware-control,dispatch}.log.
Both x86_64/aarch64 target compile checks PASS; release/features/stack not yet rerun.

Next class work must respect posted/quit, hardware, paint, timer priority.
Current state.rs peek/take share queue.peek_matching before paint;
message_queue.rs inspect_retrieval_for_thread ignores class flags.
QueuedMessage.bits already records origin; canonical timers generate
QS_TIMER entries. An arbitrary message-number filter cannot substitute for
origin classification. Any selected QS_INPUT permits the hardware scan;
individual input bits do not narrow that scan. Posted WM_TIMER remains a
posted message, distinct from a generated timer. No class runtime changes yet.
