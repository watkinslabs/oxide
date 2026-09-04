# Windows NT Named-Pipe Object Contract

DRAFT 2026-09-04. Dep:`01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`52`,`53`.

## 1 Ownership

Named pipes are NT objects, not aliases for Linux VFS FIFOs or Unix sockets.
The scheduler/object layer owns the immutable creation configuration, instance
admission count, endpoint lifetime, and transport state. A server reservation
is released by the endpoint's final NT object reference, after the last handle
to that endpoint closes; client handles never mutate the server admission
count.

This follows Wine's `server/named_pipe.c` model and Linux's separation of
pipe state from the filesystem inode. It avoids creating a second source of
truth in the NT syscall adapter.

## 2 Contract

`NtPipe::validate_create` rejects zero access, invalid sharing bits, zero
resource quotas, zero instance limits, and unknown message/read/completion
modes. `reserve_instance` and `release_instance` enforce the configured
maximum under the scheduler lock, so every handle referring to the object
observes one admission count. `NtPipeEndpoint` provides separate server and
client views over directional queues, enforces the configured quotas, reports
nonblocking backpressure, and reports peer closure as a broken pipe.

`NtCreateNamedPipeFile` now creates a server endpoint handle with the native
ABI, preserves create/open disposition, and enforces instance admission.
`NtCreateFile`/`NtOpenFile` resolve the canonical pipe object and create one
client endpoint, returning `STATUS_PIPE_BUSY` when it is already connected.
`FSCTL_PIPE_DISCONNECT` now resets the owned connection and discards queued
data, while unsupported control codes return an explicit NT status.
`FSCTL_PIPE_LISTEN` enters explicit server-listening state and returns
`STATUS_PENDING` until a client pairs with the instance.
`FSCTL_PIPE_PEEK` returns the Wine-compatible pipe-state header and a
non-consuming queue snapshot. `FSCTL_PIPE_TRANSCEIVE` validates both user
buffers and performs a directional write/read transaction when a response is
already available.
`FilePipeInformation` and `FilePipeLocalInformation` queries expose the
owner’s mode, endpoint, state, instance, quota, and queued-data fields with
strict 8-byte and 40-byte output contracts.
`FilePipeInformation` setters update read and completion mode on the specific
endpoint handle and reject values outside Wine’s one-bit contract.
Named-pipe endpoint handles can associate with the native completion-port
owner, so completed synchronous pipe operations use the same packet contract
as VFS-backed file operations; unrelated NT object types remain rejected.
Blocking-mode endpoint I/O now parks through the scheduler wait-list contract;
peer writes, reads, connect, close, and disconnect wake the corresponding
waiters. Blocking requests are registered by issuing thread and IOSB, matching
Wine's async request ownership. `NtCancelIoFile` marks that thread's pending
requests and wakes them; `NtCancelIoFileEx` marks only its matching IOSB and
returns `STATUS_NOT_FOUND` when no such request is pending. Cancelled waits
complete with `STATUS_CANCELLED`, while transport state is preserved. True
overlapped/APC request retention and completion, plus the remaining pipe FSCTLs,
stay separate work;
those paths do not fall through to VFS files.

## 3 Tests

- creation rejects zero access, invalid sharing, quotas, instance limits, and
  unsupported modes without publishing an object;
- server admission is bounded and released only by the final endpoint object
  reference; client close cannot release a server reservation;
- directional queue quotas report backpressure and peer close without
  converting a pipe into a VFS or Unix-socket operation;
- disconnect discards queued data, listen reports pending until pairing, and
  peek does not consume data;
- cancel-by-thread and cancel-by-I/O-status-block have distinct ownership and
  wake the corresponding waiters;
- invalid information buffers, unsupported FSCTLs, wrong object types, and
  repeated close/disconnect operations return their specified NT statuses;
- both kernel targets compile the shared contract, while the x86-64 Windows
  acceptance suite exercises the native pipe path.
