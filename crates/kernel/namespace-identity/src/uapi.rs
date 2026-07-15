pub const IPC_INIT_NSFS_INO: u64 = 0xEFFF_FFFF;
pub const UTS_INIT_NSFS_INO: u64 = 0xEFFF_FFFE;
pub const USER_INIT_NSFS_INO: u64 = 0xEFFF_FFFD;
pub const PID_INIT_NSFS_INO: u64 = 0xEFFF_FFFC;
pub const CGROUP_INIT_NSFS_INO: u64 = 0xEFFF_FFFB;
pub const TIME_INIT_NSFS_INO: u64 = 0xEFFF_FFFA;

pub const MNT_INIT_NSFS_INO: u64 = 0x7300_0000;
pub const NET_INIT_NSFS_INO: u64 = 0x7200_0006;
pub(crate) const FIRST_DYNAMIC_NSFS_INO: u64 = MNT_INIT_NSFS_INO + 1;

pub const IPC_INIT_NS_ID:    u64 = 1;
pub const UTS_INIT_NS_ID:    u64 = 2;
pub const USER_INIT_NS_ID:   u64 = 3;
pub const PID_INIT_NS_ID:    u64 = 4;
pub const CGROUP_INIT_NS_ID: u64 = 5;
pub const TIME_INIT_NS_ID:   u64 = 6;
pub const NET_INIT_NS_ID:    u64 = 7;
pub const MNT_INIT_NS_ID:    u64 = 8;
// Linux seeds namespace_cookie to NS_LAST_INIT_ID + 1 and allocates with
// atomic64_inc_return(), leaving 9 unused and returning 10 first.
pub(crate) const FIRST_DYNAMIC_NS_ID: u64 = 10;
