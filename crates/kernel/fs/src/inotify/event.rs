use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::InodeRef;

use crate::inotify::types::PermState;

#[derive(Default)]
pub(crate) struct Event {
    pub(crate) wd: i32,
    pub(crate) mask: u32,
    pub(crate) cookie: u32,
    pub(crate) name: Vec<u8>,
    pub(crate) obj: Option<InodeRef>,
    pub(crate) pid: u32,
    pub(crate) perm: Option<Arc<PermState>>,
    pub(crate) mnt_id: u64,
    pub(crate) dir2: Option<InodeRef>,
    pub(crate) name2: Vec<u8>,
    pub(crate) error: i32,
    pub(crate) fsid: u64,
    pub(crate) err_count: u32,
    pub(crate) range: Option<(u64, u64)>,
}
