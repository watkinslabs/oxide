// The live key/keyring store. No permission decisions here — those are
// `perm.rs`; no op policy — that is `ops/`.
//
// Module manifest:
// - types:   `struct key`, `TaskIds`, `KeyUser`, `Quota`, and the
//            `.request_key_auth` payload record.
// - state:   the `Store` maps and the lock guarding them.
// - tunables: the `/proc/sys/kernel/keys/` live values every path re-reads.
// - quota:   the `key_user` charge and refund arithmetic, and the gc.
// - mint:    `key_alloc` in each state Linux allocates a key in.
// - resolve: special-id resolution, linking, cycle detection, and the keyring
//            roots a search or possession test starts from.

mod mint;
mod quota;
mod tunables;
mod resolve;
mod state;
mod types;

pub use tunables::{max_bytes, max_keys, persistent_expiry, quota_limit, set_persistent_expiry,
    set_quota_limit, QuotaKnob};
#[cfg(test)] pub use quota::over_quota;
pub use state::{Store, STORE};
pub use types::{AuthData, Key, KeyUser, Quota, TaskIds};
