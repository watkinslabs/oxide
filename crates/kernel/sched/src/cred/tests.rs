// Hosted coverage for the credential syscalls.
//
// Module manifest:
// - fixtures: unprivileged/privileged Task builders shared by every case.
// - setuid:   setuid/setgid + setreuid/setregid transitions and EPERM order.
// - setresid: setresuid/setresgid triples, the `-1` sentinel, fsuid follow.
// - fsid:     setfsuid/setfsgid never-fail contract + fs-cap juggling.
// - groups:   getgroups/setgroups counts, sizes, sorting, and error order.
// - getres:   getresuid/getresgid writeback and EFAULT.
// - capfix:   cap_emulate_setxuid + commit_creds dumpability side effects.

mod capfix;
mod fixtures;
mod fsid;
mod getres;
mod groups;
mod setresid;
mod setuid;
