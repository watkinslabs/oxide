// genetlink test manifest.
// - `harness`:  shared registry bring-up + listener construction.
// - `registry`: family/group id allocation and registration errors.
// - `ctrl`:     the discovery path — resolve by name/id, ops, mcast groups.
// - `admit`:    request admission ordering and the permission ladder.
// - `fanout`:   multicast delivery, namespace scoping, and ESRCH.
// - `quota`:    VFS_DQUOT warning attributes end to end.

mod harness;
mod registry;
mod ctrl;
mod admit;
mod fanout;
mod quota;
