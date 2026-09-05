# Windows NT threadpool waits and timers

Status: FROZEN 2026-09-04. Dep:01,02,06,13,31g,31h,31co,52,53.

## 1

The native NT boundary owns callback-object allocation for `TpAllocWait` and
`TpAllocTimer`, process-scoped callback records for `RtlRegisterWait`, and the
first ready dispatch. A ready wait or zero-due timer is consumed through the
canonical NT object state and queued as an NT APC on the registering thread;
the existing return-to-user dispatcher invokes the user callback with its
retained context. This keeps callback execution out of IRQ and scheduler
worker context.

## 2

The callback record is process-local and retains the opaque object token,
callback address, context, wait handle, timeout, and flags. Invalid callback,
output, process-personality, handle, access, and flag inputs fail before
publication. Callback queue overflow also fails rather than claiming a
delivery that was lost.

## 3

Future timeout expiry, periodic re-arm, `TpSetWait`, `TpSetTimer`, release and
flush ordering, pool/work/I/O-completion ownership, and cleanup groups remain
explicitly unsupported. `RtlDeregisterWaitEx` validates a supplied completion
event before removing the wait, then signals that canonical event; invalid
completion handles preserve the registration for a later valid call.
