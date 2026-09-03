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
observes one admission count.

`NtCreateNamedPipeFile`, named-object publication, client opening, endpoint
I/O, and pipe FSCTLs remain explicitly unimplemented until their complete
object and asynchronous-I/O contract is added. The existing unsupported
boundary remains in place rather than returning a misleading file handle.
