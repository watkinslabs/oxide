# Windows NT PEB loader lock

Status: FROZEN
Date: 2026-08-31

`RtlAcquirePebLock` and `RtlReleasePebLock` operate on one recursive lock per
NT process. The lock is owned by thread ID, so recursive acquisition by the
owner succeeds and release by another thread is rejected. Contended acquisition
waits through the scheduler’s interruptible wait protocol.

The lock is stored on the canonical `ThreadGroup`, alongside process-wide NT
state. It does not reuse Linux process-group/job-control state and is not
visible to Linux-personality tasks. The synthetic x86-64 NTDLL page exposes
both exports; AArch64 checks validate shared ABI compilation only.
