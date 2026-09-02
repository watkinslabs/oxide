# Windows NT synchronization objects

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31f`,`52`,`53`. Provides: event state and scheduler wait integration for the native object layer.

## 1 Contract

- Native `NotificationEvent` (type 0) remains signaled until an explicit reset.
- Native `SynchronizationEvent` (type 1) releases at most one waiter per signal and retains an unconsumed signal.
- Set publishes state before waking waiters.
- Reset prevents later waits from consuming the prior signal.
- Event lifetime is owned by the NT object handle's `Arc` reference.
- Wait uses the shared scheduler predicate-wait loop, so a signal and timeout
  race is resolved by rechecking event state under the wait-list protocol.
- Timeout pointers use NT's signed 100-ns encoding: null is infinite,
  non-positive values are relative, and positive values are absolute NT epoch
  timestamps.
- A wait requires `SYNCHRONIZE`; set/reset require `EVENT_MODIFY_STATE`.
- Linux futex, poll, and signal behavior remains unchanged; NT event state uses a separate object primitive.
- Waitable NT timers use the scheduler monotonic clock, support notification
  and synchronization modes, one-shot and periodic relative deadlines, and
  are disarmed explicitly by `NtCancelTimer`.
- `NtSignalAndWaitForSingleObject` signals an event and then waits through the
  same native NT wait path, preserving alertable and timeout results.
- `NtPulseEvent` temporarily signals an event, wakes the eligible waiter(s),
  and leaves the event nonsignaled; synchronization events have one pulse
  consumer while notification events allow all current observers to consume it.

## 2 Operations

| Operation | Native owner |
|---|---|
| set | `sched::nt_object::NtEvent::set` |
| reset | `sched::nt_object::NtEvent::reset` |
| pulse | `sched::nt_object::NtEvent::pulse` |
| nonblocking consume | `sched::nt_object::NtEvent::try_wait` |
| blocking wait | NT syscall adapter over `sched::WaitList` |
| create/arm/cancel timer | `sched::nt_object::NtTimer` |
| signal and wait | native NT adapter over event and scheduler wait primitives |

## 3 Tests

- manual-reset events can be consumed repeatedly after set;
- auto-reset events can be consumed once per set;
- reset clears both event forms;
- state publication precedes scheduler wakeup.
- pulse wakeups are transient, do not make a later wait ready, and enforce the
  one-consumer rule for synchronization events;
- relative zero, negative relative, positive absolute, and minimum signed
  timeout values are decoded deterministically;
- stale handles, insufficient rights, timeout, and alertable interruption are
  mapped before event state is changed.
- one-shot timers fire once, periodic timers rearm, and cancellation clears
  readiness without affecting event objects.
