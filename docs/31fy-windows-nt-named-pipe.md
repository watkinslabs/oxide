# Windows NT Named-Pipe Object Contract

Status: IN PROGRESS

Date: 2026-09-03

## Ownership

Named pipes are NT objects, not aliases for Linux VFS FIFOs or Unix sockets.
The scheduler/object layer owns the immutable creation configuration and the
instance admission count. A later endpoint lane will add connection state,
directional queues, blocking, and FSCTL operations to this same object.

This follows Wine's `server/named_pipe.c` model and Linux's separation of
pipe state from the filesystem inode. It avoids creating a second source of
truth in the NT syscall adapter.

## Current contract

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
Handle-side blocking waits and the remaining pipe FSCTLs stay separate work;
those paths do not fall through to VFS files.
