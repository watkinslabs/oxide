// Hosted tests for the mempolicy work fns. Module manifest:
//   nodemask_tests  get_nodes / copy_nodes_to_user bit + off-by-one conventions
//   policy_tests    sanitize_mpol_flags / mpol_new admission ladder
//   query_tests     do_get_mempolicy's four reporting behaviours
//   args_tests      per-syscall argument ladders
//   scan_tests      queue_pages_range holes (EFAULT) and STRICT (EIO)

mod args_tests;
mod nodemask_tests;
mod policy_tests;
mod query_tests;
mod scan_tests;
