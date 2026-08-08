// POSIX message-queue POLICY — the decision rules of `mq_open(2)`,
// `mq_unlink(2)`, `mq_notify(2)` and `mq_getsetattr(2)`, kept OUT of the
// kernel-only `live::posix_mq` tree so every errno ladder is hosted-tested:
// a `#[cfg(test)]` block inside a `target_os = "oxide-kernel"` file compiles
// out silently and never runs.
//
// Module manifest:
// - `limits`: mqueue sysctl defaults + hard caps.
// - `name`:   the queue-name lookup ladder (component/length/empty-string rules).
// - `open`:   existence/access-mode resolution (`prepare_open` + `OPEN_FMODE` shape).
// - `attr`:   inode/attr validation + the
//             RLIMIT_MSGQUEUE arithmetic.
// - `notify`: the sigevent validation gate for registration.

pub mod attr;
pub mod limits;
pub mod name;
pub mod notify;
pub mod open;

#[cfg(test)]
mod tests;
