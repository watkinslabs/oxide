// POSIX message queues (`24`) — slots 240..=245.
//
// Each IPC namespace owns a private mqueuefs
// whose sticky 01777 root holds one `S_IFREG` inode per queue; the inode's
// private state IS the queue, its mode/uid/gid are what `mq_open` and
// `mq_unlink` run DAC against, and the descriptor's own flags carry the access
// mode and `O_NONBLOCK`. Nothing here keeps a second name-keyed table.
//
// Module manifest:
// - `model`:         per-namespace directories, the queue object, inode
//                    creation/linking, `queues_max` + RLIMIT_MSGQUEUE accounting.
// - `fops`:          `mqueue_file_operations` — `read`, `poll`, `flush`, `release`.
// - `open`:          `mq_open(2)` + `mq_unlink(2)`.
// - `sendrecv`:      `mq_timedsend(2)` + `mq_timedreceive(2)`.
// - `notify`:        `mq_notify(2)` registration + `__do_notify` delivery.
// - `thread_notify`: the SIGEV_THREAD netlink socket bridge.
// - `attr`:          `mq_getsetattr(2)`.
// - `sysctl`:        the `/proc/sys/fs/mqueue/*` leaves.
// - `wait`:          the blocking edge (`prepare_timeout`, `wq_sleep`'s verdict).
// - `user`:          user-memory access + current-task snapshots.

mod attr;
mod fops;
mod model;
mod notify;
mod open;
mod sendrecv;
pub mod sysctl;
mod thread_notify;
mod user;
mod wait;

pub use attr::sys_mq_getsetattr;
pub use notify::sys_mq_notify;
pub use open::{sys_mq_open, sys_mq_unlink};
pub use sendrecv::{sys_mq_timedreceive, sys_mq_timedsend};

pub(crate) use model::reap_namespace;
