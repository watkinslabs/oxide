# Windows NT search-path mode

Status: FROZEN
Date: 2026-08-31

`RtlSetSearchPathMode` stores one process-scoped mode in the native NT
thread-group state. The accepted flags are enable-safe (`0x00001`),
disable-safe (`0x10000`), and enable-safe-permanent (`0x08001`). Other values,
including the permanent bit by itself, return `STATUS_INVALID_PARAMETER`.

The permanent state is monotonic: once published, later non-permanent changes
return `STATUS_ACCESS_DENIED`; repeating enable-safe-permanent succeeds. The
state update uses an atomic compare-and-exchange loop so concurrent NT threads
cannot overwrite a permanent transition.
