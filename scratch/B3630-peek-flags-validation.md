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

Class runtime now uses canonical QueuedMessage origins. Both actual Peek
copy/removal calls carry full flags; hardware/live passes flags into canonical
inspection. Existing default wrappers use the same owner. Posted entries
precede input regardless of insertion order; selected input class admits the
hardware scan; excluded paint remains pending; generated timers follow paint.
Get and Peek share fallback selection. Owner1559 and dispatcher149 passed
before controls. Three controls (adapter drops flags, hardware ignores upper
word, timer classification uses number instead of origin) each ran exactly
one failing intended test; all sources restored. Final suites/builds pending.
Logs /tmp/B3630-peek-classes-{ipc,dispatch,control-dispatch,control-hardware,
control-origin}.log. Live hardware ladder still lacks direct hosted coverage
for upper flags; target build and final desktop verification required.

Final restored owner1559, syscall library3276 and dispatcher149 PASS.
Builds/features running; stack comparison pending against retrieval-paint ELFs.
