# Windows NT Set Debug Object Information

Status: FROZEN

Date: 2026-08-31

## Contract

The native 64-bit export is present as selector 117. Wine uses this service
to update `DebugObjectKillProcessOnExitInformation` on a debug-object
handle. Oxide does not yet provide native debug-object identity, event
queues, or kill-on-close state, so the service returns explicit
`STATUS_NOT_IMPLEMENTED` for the NT personality.

Linux ptrace state is not substituted for Windows debug-object semantics.
