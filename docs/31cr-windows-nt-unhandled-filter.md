# Windows NT unhandled-exception filter

Status: FROZEN
Date: 2026-08-31

`RtlSetUnhandledExceptionFilter` stores one process-scoped callback address
in native NT thread-group state. A null address clears the filter; a non-null
address must be a valid user address. The setter returns success after the
atomic publication and does not alter Linux signal dispositions.

Exception dispatch must consume this same stored address when the native
exception path reaches its unhandled-filter decision. Calling the user filter
with a complete `EXCEPTION_POINTERS` frame remains a follow-up boundary; the
setter and ownership contract are implemented here so that later dispatch
cannot introduce a second filter registry.
