# Canonical paint status lifecycle

| Status | Branch | Work |
|---|---|---|
| IMPLEMENTED | B3630-paint-region-collapse | KI0915 paint arrival/status lifecycle |
| IMPLEMENTED | B3630-paint-region-collapse | KI0913 stored and observed retrieval acknowledgement |
| OPEN | B3630-paint-region-collapse | Final release/frame/static validation |

Queue status no longer synthesizes changed paint from pending paint. Existing
queue.changed owns acknowledgement. Region presence and internal paint are
independent obligations in canonical PaintDamage. An obligation transition
sets changed if any paint remains for its thread, including decrement while
another request remains; draining clears changed. Expanding existing region
coverage or repeating an already-set internal flag does not rearm changes.
Wake state derives from existing damage without allocation or a copied count.

Mutation hooks: redraw_damage, begin_paint (including parent validation),
take_erase_damage, take_pending_paint, apply_position_preserving and
remove_window before revoking window ownership. No new WindowManager state.
Nine owner tests exercise queries, excluded flags, regions, both internal
states, different threads, decrement/rearm, last-drain, nonclient erase,
parent validation, positioning and destruction. Four fail on original query
behavior. Actual dispatcher nonremoving Peek acknowledges paint while keeping
the region pending through repeated retrieval. This closes the observed paint
gap in the previous retrieval-status adapter.

Final IPC1557/syscall3276 library tests PASS; dispatcher145, wait/status35,
send70, redraw50/9, scroll56, raw paint29, null paint35 PASS. Increased redraw/
null counts include six shared sent-status tests. No guest DLL executes.
Five retrieval controls and nine paint controls each execute one failing
intended test; all production mutations restored before final green suites.
Paint controls remove query independence or each mutation hook, or collapse
region/internal obligations to one boolean. Retrieval controls remove wiring,
change ordering/range/classes, or acknowledge before invalid HWND validation.
Logs /tmp/B3630-control-{retrieval-wiring,retrieval-order,retrieval-range,
retrieval-classes,retrieval-invalid,paint-query,paint-redraw,paint-begin,
paint-parent,paint-erase,paint-internal,paint-position,paint-destroy,
paint-obligations}.log and /tmp/B3630-paint-status-{red,ipc,final-tests}.log.

Combined release/features/frame/static validation running. Retrieval scalar
argument correction69a28bc7b must remove the initial dispatcher16B growth;
compare final ELFs against posted-status baseline, not the larger intermediate
retrieval build. No stack exception beyond existing KI0019 is permitted.

Peek class/removal flags KI0914, wait flags KI0712, object acquisition/timer
deadlines KI0912 and handle stride KI0844 remain. No VM launched. Complete
Notepad About/Open/Save/menus/borders/buttons acceptance remains outstanding.
