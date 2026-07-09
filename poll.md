# Poll / epoll / AF_UNIX analysis

Scope: code analysis only. This ignores spec text and compares the current implementation shape to Linux's poll/eventpoll model.

## Current boot symptom

Observed frontier: `systemd-tmpfiles-setup-dev-early` waits in `epoll_wait` after sending a varlink userdb query, apparently `GetMemberships("lp")`, through socket activation to `systemd-userdbd.socket`.

Important trace facts from the handoff:

- tmpfiles connects.
- tmpfiles sees writable connect completion / `POLLOUT`.
- tmpfiles sends the request.
- `systemd-userdbd` exists but sits idle for a long time.
- reply arrives much later, so the service path is not permanently dead.
- likely failure window: listener/accepted-socket readiness does not wake the epoll waiter promptly.

The failure class is not "does `poll()` compute readiness correctly?" in isolation. The listener `poll()` path does return `POLL_IN` once `accept_q` is non-empty. The suspicious area is the wake path that is supposed to make the epoll waiter run a scan.

## Linux model

Linux does not have event sources manually remember "the epoll for this socket" as a side channel.

The shape is:

1. `epoll_ctl(ADD)` creates an `epitem`.
2. It calls the target file's `poll()` with a `poll_table`.
3. The target file's `poll()` calls `poll_wait(file, waitqueue, poll_table)` for every waitqueue that can change its readiness.
4. `ep_poll_callback()` is installed on those waitqueues for that specific epitem.
5. Event producers mutate state, then wake the same waitqueue.
6. The callback queues the epitem on the epoll ready list and wakes `epoll_wait`.
7. `epoll_wait` returns the ready item. Readiness is still revalidated through `poll()` semantics.

Two important consequences:

- The wake registration is per watched file/epitem, not just per epoll instance.
- Event producers do not need to know which epoll or socket object is watching. They wake their own waitqueue.

## Current implementation shape

Relevant files:

- `crates/kernel/fs/src/epoll.rs`
- `crates/kernel/vfs/src/poll_subs.rs`
- `crates/kernel/net/src/unix_sock/listener.rs`
- `crates/kernel/net/src/unix_sock/stream.rs`
- `crates/kernel/net/src/unix_sock/events.rs`
- `crates/kernel/net/src/sock/ops.rs`
- `crates/kernel/net/src/sock/inode.rs`
- `crates/kernel/net/src/sock/io.rs`

Current model is custom:

- Each socket has `InetSocket.poll_subs: Arc<PollSubscribers>`.
- `make_inet_socket_inode()` shares that exact `poll_subs` into the inode with `.poll_subs_arc(subs)`.
- `epoll_ctl(ADD)` asks `target_inode.poll_subscribers()` and subscribes the epoll to that list.
- AF_UNIX listener `bind()`/`listen()` also caches the same subscriber list into `UnixListener.subs`.
- `UnixRegistry::connect()` pushes into `listener.accept_q`, wakes blocking `accept_waiters`, then calls `listener.notify_subs()`.
- AF_UNIX stream writes call `wake_peer_subs()`, which uses `UnixPair.end_a_subs/end_b_subs`, registered when the connected/accepted socket object is created.

This is not Linux's waitqueue registration model. It is a manually wired subscriber graph.

## Concrete code issues

### 1. `epoll_ctl(ADD)` subscribes by epoll id, not epitem id

In `fs/src/epoll.rs`, `sys_epoll_ctl(ADD)` does:

```rust
subs.subscribe(ep.id, weak);
```

`PollSubscribers::subscribe_flags()` treats `id` as unique and replaces an existing subscription with the same id:

```rust
if s.id == id { s.wake = wake; s.mask = mask; s.exclusive = exclusive; return; }
```

That means the uniqueness key is the epoll instance, not the watched fd / epitem.

Linux has one callback per epitem. A single epoll can watch many fds backed by the same underlying waitqueue and must still retain independent interest/mask/data/edge state for each watched fd. The current subscriber key cannot express that. If two watched fds share the same `PollSubscribers`, the second add replaces the first subscriber entry.

For the userdbd/tmpfiles case this may or may not be the exact trigger, depending on whether the same epoll has multiple fds sharing one `PollSubscribers`. But the model is wrong and can lose wake coverage in exactly the kind of sd-event loop systemd uses.

Fix direction:

- Give each `EpollEntry` a unique subscription id, not `ep.id`.
- Store that id in `EpollEntry`.
- Use it for ADD/MOD/DEL unsubscribe.
- Preserve `ep.id` only as the epoll instance id.

### 2. `EPOLL_CTL_MOD` updates the entry but not `PollSubscribers`

In `fs/src/epoll.rs`, `EPOLL_CTL_MOD` only mutates:

```rust
e.events = events;
e.data = data;
e.et_seen = 0;
return 0;
```

It does not update the subscription mask in `PollSubscribers`.

That is not Linux-shaped. `ep_modify()` changes the callback interest key/mask semantics for that epitem. In this implementation, if `notify_mask()` is used by an event source, it can wake or skip based on stale interest.

Current socket paths often call plain `notify()`, which wakes all subscribers and masks later during scan. But `PollSubscribers` has `notify_mask()` and tests for mask filtering, so stale MOD behavior is a latent correctness bug.

Fix direction:

- On MOD, call `subscribe_mask()` / `subscribe_exclusive()` again with the same epitem subscription id and the new events.
- Reset `last_gen`/`last_ggen` coherently when changing edge-triggered interest.

### 3. `EPOLLEXCLUSIVE` is implemented in `PollSubscribers` but not wired from epoll flags

`PollSubscribers` has `subscribe_exclusive()`, and tests exist. `epoll_ctl(ADD)` never appears to parse `EPOLLEXCLUSIVE`; it always calls `subs.subscribe(ep.id, weak)`.

Linux uses `EPOLLEXCLUSIVE` mostly for accept loops. This may not be the tmpfiles/userdbd single-service case, but it is another sign the implementation is not using an epitem-like waitqueue registration model.

Fix direction:

- Define the Linux `EPOLLEXCLUSIVE` bit.
- On ADD/MOD, register exclusive vs non-exclusive based on event flags.
- Strip/handle non-readiness epoll flags consistently when computing interest.

### 4. Listener readiness wake is a cached side pointer

`UnixListener` stores:

```rust
pub subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, UnixLockClass>
```

It is set by `listener.register_subs(&sock.poll_subs)` during bind/listen.

`UnixRegistry::connect()` does:

```rust
listener.accept_q.lock().push_back(pair.clone());
listener.accept_waiters.wake_all();
listener.notify_subs();
```

Linux would instead wake the listener socket's accept waitqueue. Epoll is registered on that waitqueue by `poll_wait()` when the listener fd is added. No listener-global cached epoll pointer is needed.

The current approach can fail if:

- the listener was created/bound in one process and passed to another process, and registration timing does not match when the receiver epolls it;
- the fd/inode/socket object observed by epoll is not the one cached in `UnixListener.subs`;
- `EPOLL_CTL_ADD` happens after `connect()` queued readiness but before any new notification, relying only on scan behavior;
- subscription replacement by `ep.id` loses the relevant waiter.

The code tries to compensate with 20 ms rescans in `epoll_wait`, but that is a safety net, not Linux semantics. The delayed reply around tens of seconds is consistent with missed direct wakes plus eventual unrelated/rescan/timer-driven progress.

Fix direction:

- Treat `UnixListener` as owning a real readiness waitqueue/subscriber list.
- Have listener `poll()` register epoll interest against the listener's own waitqueue/subs, not a socket object's side pointer.
- Have `connect()` wake that listener waitqueue after pushing `accept_q`.
- Or, as an incremental repair, make `UnixListener.subs` an `Arc<PollSubscribers>` owned by the listener and make the listener socket inode use that same arc for epoll subscription while in `SockKind::UnixListener`.

### 5. Accepted stream sockets are registered before fd installation, but Linux relies on poll registration after userspace adds the fd

In `sock/ops.rs`, AF_UNIX `accept()` does:

```rust
pair.register_end_subs(UnixEnd::A, &new_sock.poll_subs);
*new_sock.kind.lock() = SockKind::Unix(pair, UnixEnd::A);
```

Then `sys_accept` wraps `new_sock` in an inode/file/fd.

This is probably okay for the common case because `new_sock.poll_subs` is stable and later `make_inet_socket_inode()` shares it into the inode. But the pattern is still inverted versus Linux: the stream pair stores the socket's subscriber list before epoll has subscribed to it.

If a peer writes before the server adds the accepted fd to epoll, `wake_peer_subs()` calls `subs.notify()` on an empty subscriber list. The later `epoll_ctl(ADD)` must then rely on the immediate scan in `epoll_wait` to see already-buffered data. That is legal for level-triggered and initial EPOLLET add, but the code's custom EPOLLET generation tracking makes this sensitive to `last_gen` initialization and prior `et_seen` state.

Fix direction:

- Ensure `epoll_ctl(ADD)` reports already-ready fds on the next wait regardless of missed prior generation increments.
- Avoid using generation changes as the only edge source. Linux queues ready epitems from callback but still has explicit add-time readiness handling.

### 6. `recvmsg_unix_stream()` busy-yields instead of parking on the stream waitqueue

For AF_UNIX stream `recvmsg`, the code uses a loop with:

```rust
unsafe { sched::live::tick_yield(); }
```

It does not use `UnixPair::read_or_park()` / `reader_waiters`.

This is not directly an `epoll_wait` wake bug, but it matters for userdbd because once the service wakes and accepts, the request read path may spin/yield instead of sleeping on the correct stream waitqueue. Linux `recvmsg` blocks on the socket waitqueue.

Fix direction:

- Make stream recvmsg use the same race-free prepare-to-wait logic as blocking read, including deadline/signal behavior.
- Keep nonblocking behavior returning `EAGAIN` for dbus/systemd edge-drain loops.

## Most likely root cause for the tmpfiles/userdbd frontier

The highest-probability implementation bug is not the `GetMemberships("lp")` protocol itself. It is the event delivery chain:

```text
tmpfiles connect()
  -> UnixRegistry::connect()
  -> listener.accept_q push
  -> listener.notify_subs()
  -> EpollData.waiters.wake_all()
  -> userdbd epoll_wait returns
  -> userdbd accept/read/reply
```

The listener queue state is correct, but the wake path is non-Linux and fragile:

- epoll subscriptions are keyed by epoll instance instead of epitem;
- listener wake uses a cached weak subscriber pointer instead of a listener waitqueue registration;
- MOD/exclusive behavior is incomplete;
- delayed rescue depends on periodic rescans rather than the readiness waitqueue.

This explains "poll would say ready if scanned" plus "service remains idle in epoll_wait".

## Recommended fix plan

Do not add protocol hacks for `GetMemberships("lp")`.

Fix the event model in the smallest Linux-shaped steps:

1. Add per-epoll-entry subscription ids.
   - `EpollEntry { sub_id: u32, ... }`
   - global/static allocator next to `NEXT_EPOLL_ID`, or per-epoll counter.
   - ADD subscribes with `sub_id`.
   - DEL unsubscribes with `sub_id`.
   - MOD re-subscribes same `sub_id` with updated mask/exclusive flag.

2. Wire event flags correctly.
   - Use readiness bits for mask matching.
   - Carry `EPOLLET` for scan behavior but do not let it become a fake readiness bit.
   - Add `EPOLLEXCLUSIVE` support if the bit is accepted.

3. Make AF_UNIX listener readiness own its wake source.
   - Prefer `UnixListener` owns `Arc<PollSubscribers>`.
   - Listener socket inode should expose that same arc while it is a listener.
   - `connect()` should wake the listener-owned wait source after `accept_q` push.
   - This removes the cached weak side pointer to the original socket poll_subs.

4. Add a hosted repro before booting.
   - Create AF_UNIX listener.
   - Add listener fd to epoll with `EPOLLIN | EPOLLET`.
   - Connect one client, consume event, accept until `EAGAIN`.
   - Connect another client while the listener remains level-ready or after edge state has been set.
   - Assert the epoll waiter is notified and scan reports listener readiness.
   - Add a variant with multiple fds from the same epoll sharing a `PollSubscribers` to prove the `ep.id` replacement bug.

5. Then boot once with a narrow trace.
   - Trace `epoll_ctl ADD/MOD/DEL`: ep id, fd, sub id, inode, event flags.
   - Trace `UnixRegistry::connect`: listener path, accept_q len, subscriber count/gen before/after notify.
   - Trace `epoll_wait` for userdbd only: woke vs timeout/rescan, scan result for listener fd.

## What not to do

- Do not special-case `lp`.
- Do not special-case `GetMemberships`.
- Do not extend the 20 ms epoll rescan workaround.
- Do not add more global epoll broadcasts as the primary fix.
- Do not rely on boot traces before adding a deterministic hosted repro for listener wake semantics.

## Bottom line

The code computes listener readiness correctly but does not model Linux poll waitqueue registration correctly. The current subscriber graph is manually wired and keyed too coarsely. For socket activation, the Linux way is: epoll registers an epitem callback on the listener socket waitqueue; connect wakes that waitqueue after queuing the connection. This repo should move AF_UNIX listener/stream readiness toward that shape rather than patching userdb protocol behavior.
