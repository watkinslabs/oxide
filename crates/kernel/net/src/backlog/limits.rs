// Tunables of the RX bottom half. Values match the reference defaults so a
// workload tuned against Linux behaves the same here; `/proc/sys/net/core`
// names are given for each.

/// `net.core.netdev_max_backlog` — per-CPU input-queue cap. The reference
/// admits while `qlen <= max_backlog`, i.e. the queue can hold one entry more
/// than the number itself; [`super::queue::SoftnetData::enqueue`] encodes that
/// off-by-one deliberately.
pub const NETDEV_MAX_BACKLOG: usize = 1000;

/// `net.core.dev_weight` — packets one poll of the backlog may deliver before
/// yielding to the next entry on the poll list.
pub const DEV_RX_WEIGHT: usize = 64;

/// `net.core.netdev_budget` — packets ALL poll entries together may deliver in
/// one softirq run before the drain re-raises itself and returns.
pub const NETDEV_BUDGET: usize = 300;

/// Upper bound on device poll entries registered with [`super::napi`]. One per
/// interrupt-driven RX driver; the loopback poll list is per-stack and is not
/// counted here.
pub const NAPI_POLL_SLOTS: usize = 8;

/// Columns in one `/proc/net/softnet_stat` row.
pub const SOFTNET_COLUMNS: usize = 15;
