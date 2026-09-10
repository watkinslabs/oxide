# WinEvent chain continuation

| Status | Branch | Work |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0907 notification delivery prerequisites for KI0904 |

HookRegistry holds a per-chain lease over local/global tables. Removal retains
an inert cursor while a walk is active; enumeration/counting skips it. Last
lease release reclaims deleted records. No second hook registry. New local
hooks ahead of an active cursor are not replayed; entering the global scope
reads its current head, including hooks installed during the local callback.

hook_api::hook_notify_win_event admits a saved notification under the existing
HOOKS lock. Each client callback carries kind0x82 plus the notification token.
callbacks::complete_callback routes it back to hook_complete_event; the owner
continues using the original event/range filter. Callback results and failed
callback admission do not stop the walk. Client entry and outer continuation
run outside the owner lock. Thread cleanup releases pending leases before
removing its hooks. Existing optional Send continuation is retained for the
EnableWindow caller; that caller is not yet wired.

Actual adapter/state/client-record/completion-router fixture:
`cargo test -p syscalls --test nt_hook_event_chain --test nt_win_event_callback`
7 chain +4 record tests PASS. Scheduler/client-execution seams; no real DLL
callback or raw ordinal execution. Cases: order, ranges, preserved event,
self-removal, removed successor, local/global insertion, nesting, failed
callback admission, exiting announcer. Production registry lifetime tests5;
full IPC1537 and syscall library3270 PASS. Both feature checks PASS.

Positive controls: remove actual completion routing ->5 failures; physically
remove an active cursor ->3 failures. Added original-event case: test-only
copy using previous hook's lower event bound ->1 failure. Runtime source
was restored before kernel builds; test-copy fixture restored and removed.
Final7+4 PASS. Logs /tmp/B3630-hook-chain-{live,ipc,ipc-full,syscalls-full,
control-route,control-lifetime,control-event,feature}.log.

Remaining: out-of-context hooks still need owner-thread queuing/pumping;
full client execution and ARM callback continuation remain unverified/open.
EnableWindow WM_CANCELMODE/event/focus/WM_ENABLE sequence remains KI0904.
No VM; Notepad About/Open/Save/menus/redraw acceptance remains outstanding.
