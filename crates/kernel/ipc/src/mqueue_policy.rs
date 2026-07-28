// POSIX message-queue POLICY — the decision rules of `mq_open(2)`,
// `mq_unlink(2)`, `mq_notify(2)` and `mq_getsetattr(2)`, kept OUT of the
// kernel-only `live::posix_mq` tree so every errno ladder is hosted-tested:
// a `#[cfg(test)]` block inside a `target_os = "oxide-kernel"` file compiles
// out silently and never runs.
//
// Module manifest:
// - `limits`: Linux mqueue sysctl defaults + hard caps (`include/linux/ipc_namespace.h:118-126`).
// - `name`:   the queue-name ladder (`fs/namei.c` `lookup_noperm_common`, `fs/libfs.c` `simple_lookup`).
// - `open`:   `prepare_open` + `OPEN_FMODE` (`ipc/mqueue.c:861-886`).
// - `attr`:   `mqueue_get_inode` / `mqueue_create_attr` validation + the
//             RLIMIT_MSGQUEUE arithmetic (`ipc/mqueue.c:289-401`, `:566-608`).
// - `notify`: `do_mq_notify`'s sigevent gate (`ipc/mqueue.c:1278-1290`).

pub mod attr;
pub mod limits;
pub mod name;
pub mod notify;
pub mod open;

#[cfg(test)]
mod tests;
