# WinEvent delivery repair

| Status | Branch | Work |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0907 event delivery prerequisites for KI0904 |

Existing nt_rtl::kernel_callback::begin already retains Completion and calls
the client callback table. Use that entry with the event argument record so
the client resolves module-relative hooks and owns module lifetime. Direct
hook callback extension removed after this existing path was identified.

Current hook_api selects only the first event hook and directly enters its
stored address. This is invalid for module-relative addresses. Full chain
resumption and out-of-context owner-thread delivery also remain missing.

EnableWindow must wait for WM_CANCELMODE before style mutation/return-state
capture; event completion before rereading focus; CBT veto and WM_KILLFOCUS
before WM_ENABLE. SB_CTL refresh follows completion. Current state helper
clears focus prematurely. Notepad acceptance remains unproven; no new VM.
