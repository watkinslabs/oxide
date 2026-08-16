// genetlink test manifest.
// - `harness`:  shared registry bring-up + listener construction.
// - `registry`: family/group id allocation and registration errors.
// - `ctrl`:     the discovery path — resolve by name/id, ops, mcast groups.
// - `admit`:    request admission ordering and the permission ladder.
// - `handlers`: a family serving its own commands through its op table.
// - `fanout`:   multicast delivery, namespace scoping, and ESRCH.
// - `quota`:    VFS_DQUOT warning attributes end to end.
// - `tcp_metrics`: cache-backed TCP metrics GET replies.

mod harness;
mod registry;
mod ctrl;
mod admit;
mod handlers;
mod fanout;
mod quota;
mod tcp_metrics;
