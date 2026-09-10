# Canonical paint status lifecycle

| Status | Branch | Work |
|---|---|---|
| IMPLEMENTED | B3630-paint-region-collapse | KI0915 paint arrival/status lifecycle |
| IMPLEMENTED | B3630-paint-region-collapse | KI0913 stored and observed retrieval acknowledgement |
| VERIFIED | B3630-paint-region-collapse | Final release/frame/static validation; baseline static failures unchanged |

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

Combined final release builds and feature gate PASS on both architectures.
Both frame gates PASS. Static gates retain baseline exit1: x86 335->335,
ARM 278->278 primary rows; no added rows or increased depths against
posted-status baseline. Scalar correction69a28bc7b removes initial16B growth.
Existing KI0019 exception remains; no new stack exception introduced.
Logs /tmp/B3630-retrieval-paint-{feature,build-x86_64,build-aarch64,
frame-x86,frame-arm,stack-x86,stack-arm}.log.
Final runtime94522894c ELF SHA256:
- x86_64:4c8c1ec653e795313112cb45a2eaa44536e880ed7262a5b93713fcff3fb4b554
- aarch64:ffe0b3ad1b6f08198bdc59dd57440b3c5690629aaa7596ce4f888dedfb58e7d6

Peek class/removal flags KI0914, wait flags KI0712, object acquisition/timer
deadlines KI0912 and handle stride KI0844 remain. No VM launched. Complete
Notepad About/Open/Save/menus/borders/buttons acceptance remains outstanding.
