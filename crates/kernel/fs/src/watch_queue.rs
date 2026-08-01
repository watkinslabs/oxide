// Watch queues — the notification mechanism a `pipe2(O_NOTIFICATION_PIPE)`
// pipe carries, and the delivery path key notifications use.
//
// A notification pipe is not a byte stream: it holds fixed-size RECORDS, a
// reader gets whole records or ENOBUFS, and nothing may be written into it
// from userspace. What is queued comes from the kernel objects a caller has
// asked to watch.
//
// Module manifest:
// - uapi:     record layout, notification types, filter limits, ioctl numbers.
// - queue:    the queue itself — depth, the notes, the filter it applies, and
//             the loss accounting that tells a reader it missed something.
// - filter:   which records a queue accepts, and the rules a filter must obey.
// - watch:    the watch list an object carries, and the add/remove rules.
// - registry: which pipes are notification pipes.
// - ioctl:    the two ioctls' copy-in.
// - pipe_ops: what a notification pipe does instead of what a pipe does —
//             record reads, the poll mask, and the refusal to be written to.
//
// Every decision here is target-independent, so the hosted tests drive the
// whole mechanism — depth, filtering, loss ordering, watch bookkeeping —
// without a pipe, a task or user memory.

pub(crate) mod filter;
mod ioctl;
mod pipe_ops;
pub(crate) mod queue;
mod registry;
mod uapi;
pub(crate) mod watch;

pub use filter::{Filter, TypeFilter};
pub use ioctl::handle_ioctl as handle_watch_queue_ioctl;
pub use queue::{header, key_notification, loss_record, removal_record, WatchQueue};
pub use pipe_ops::{poll_mask, read_nb, write_refused};
pub use registry::{attach, detach, is_notification_pipe, queue_of};
pub use uapi::*;
pub use watch::{Watch, WatchList};

#[cfg(test)] mod tests;
