// Credential-ABI sentinels and validity predicates
// (Linux `include/linux/uidgid.h` `INVALID_UID`/`uid_valid`).

/// `(uid_t)-1` / `(gid_t)-1`. Two distinct roles in the Linux ABI:
///   * `set{re,res}{u,g}id` — "leave this id unchanged".
///   * every other position — an INVALID id (`make_kuid` yields
///     `INVALID_UID`), so `setuid(-1)`/`setgid(-1)` are `EINVAL` and a
///     `setgroups` list entry of `-1` is `EINVAL`.
pub const ID_UNCHANGED: u32 = u32::MAX;

/// Linux `uid_valid()` / `gid_valid()`: every id but `(uid_t)-1` is valid.
/// # C: O(1)
pub const fn id_valid(id: u32) -> bool { id != ID_UNCHANGED }

/// Linux `getgroups(2)`/`setgroups(2)` narrow their first argument to `int`
/// before use (`SYSCALL_DEFINE2(getgroups, int, gidsetsize, ...)`), so the
/// upper half of the syscall register is discarded, NOT rejected.
/// # C: O(1)
pub const fn gidsetsize(raw: u64) -> i32 { raw as u32 as i32 }
