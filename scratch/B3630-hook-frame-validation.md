# WinEvent delivery repair

| Status | Branch | Work |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0907 event delivery prerequisites for KI0904 |

Existing nt_rtl::kernel_callback::begin already retains Completion and calls
the client callback table. Use that entry with the event argument record so
the client resolves module-relative hooks and owns module lifetime. Direct
hook callback extension removed after this existing path was identified.

hook_api::hook_notify_win_event now constructs the event notification and
calls hook_event::begin, which invokes client callback-table index3 with the
48-byte header plus terminated UTF-16 module path. Stored relative procedure
is passed unchanged for client resolution. Raw notify propagates pending
status. Removed unused direct WinEvent callback entry. Full chain resumption
and out-of-context owner-thread delivery remain missing (KI0907 stays open).

`cargo test -p syscalls --test nt_win_event_callback`: 4 PASS. Fixture compiles
the production event entry and instruments begin_user_callback. Verifies
callback index, full-width HWND/procedure/completion, signed object/child,
32-bit thread/time, empty/embedded-NUL/maximum module paths. Removing callback
entry fails all4; dropping module fails3; source restored, 4 PASS.
Logs /tmp/B3630-win-event-{tests,control-dispatch,control-module}.log.
This fixture does not execute client DLL loading, actual callback return,
raw ordinal or registry selection. Those live call sites were source-audited.

EnableWindow must wait for WM_CANCELMODE before style mutation/return-state
capture; event completion before rereading focus; CBT veto and WM_KILLFOCUS
before WM_ENABLE. SB_CTL refresh follows completion. Current state helper
clears focus prematurely. Notepad acceptance remains unproven; no new VM.
