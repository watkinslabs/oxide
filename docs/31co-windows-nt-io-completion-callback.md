# Windows NT I/O completion callback

Status: FROZEN
Date: 2026-08-31

`RtlSetIoCompletionCallback` is implemented as a native x86-64 NT boundary.
It validates the process-local file handle, callback address, and reserved
flags, then binds the canonical NT file object to a process-owned completion
port. Synchronous native file reads and writes publish completion packets with
the callback key, I/O status, byte count, and I/O-status address as the
internal overlapped value.

The port is retained by the thread group because this RTL API does not return
an application-visible completion-port handle. Callback-thread dispatch and
the complete asynchronous `OVERLAPPED` ABI remain follow-up work; the binding
and packet publication are deliberately testable independently of that
dispatcher.

The implementation follows Wine's old-threadpool shape: create one private
completion port, use the callback address as the completion key, and associate
the file through native completion state. The native object model owns the
association, so closing or duplicating the handle cannot create a second file
description with divergent completion state.
