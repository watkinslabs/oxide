use super::*;
use core::sync::atomic::{AtomicU8, Ordering};

static SEEN: AtomicU8 = AtomicU8::new(0);

fn record(timeout: FsTimeout) {
    SEEN.store(timeout as u8 + 1, Ordering::Release);
}

#[test]
fn timeout_is_forwarded_to_the_installed_owner() {
    clear_fs_timeout_hook();
    assert!(!fs_timeout(FsTimeout::Running));
    set_fs_timeout_hook(record);
    assert!(fs_timeout(FsTimeout::Runnable));
    assert_eq!(SEEN.load(Ordering::Acquire), FsTimeout::Runnable as u8 + 1);
    clear_fs_timeout_hook();
}
