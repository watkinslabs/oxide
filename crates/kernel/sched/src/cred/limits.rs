// Credential-ABI sentinels and validity predicates
// (Linux's `INVALID_UID` sentinel and `uid_valid` predicate).

/// `(uid_t)-1` / `(gid_t)-1`. Two distinct roles in the Linux ABI:
///   * `set{re,res}{u,g}id` — "leave this id unchanged".
///   * every other position — an INVALID id, which is what `make_kuid`
///     yields for it in EVERY namespace (the initial namespace's identity
///     extent deliberately stops one id short). The validity test therefore
///     belongs to the namespace translation in `cred::userns`, not here:
///     `setuid(-1)` is `EINVAL` because nothing maps it, exactly as an
///     out-of-range id in a container is.
pub const ID_UNCHANGED: u32 = u32::MAX;

/// Linux `getgroups(2)`/`setgroups(2)` narrow their first argument to `int`
/// before use (`SYSCALL_DEFINE2(getgroups, int, gidsetsize, ...)`), so the
/// upper half of the syscall register is discarded, NOT rejected.
/// # C: O(1)
pub const fn gidsetsize(raw: u64) -> i32 { raw as u32 as i32 }
